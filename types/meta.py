from binaryninja import BinaryView, TypedDataAccessor
from binaryninja.types import Type, TypeBuilder, BaseStructure

from types import new_class

from ..heap import SvmHeap
from .layout_encoding import LayoutEncoding

class SubstrateTypeMeta(type):
    _type_registry: dict[BinaryView, dict[str, 'SubstrateType']] = {}
    _hub_mappings: dict[BinaryView, dict[int, 'SubstrateType']] = {}
    _meta_specialisations: dict[str, 'SubstrateType'] = {}

    def __call__(cls, name, bases, *args, view: BinaryView | SvmHeap, **kwargs):
        instances = cls._type_registry.setdefault(
            view if isinstance(view, BinaryView) else view.view,
            {}
        )
        if (type_name := getattr(cls, 'raw_name', kwargs.get('raw_type_name'))) is None:
            raise TypeError('Could not resolve name')

        if type_name not in instances:
            target = cls
            if type_name in cls._meta_specialisations:
                target, base_spec = cls._meta_specialisations[type_name]

                if isinstance(base_spec, tuple):
                    bases = (*bases, *base_spec)
                    name = base_spec[0].__name__
                elif base_spec is not None:
                    bases = (*bases, base_spec)
                    name = base_spec.__name__

            instances[type_name] = super(
                SubstrateTypeMeta,
                target,
            ).__call__(name, bases, *args, view=view, **kwargs)

        return instances[type_name]

    def get_hub_mapping(cls, view: BinaryView):
        return cls._hub_mappings.setdefault(view, {})

class SubstrateType(type, metaclass=SubstrateTypeMeta):
    heap: SvmHeap

    raw_name: str
    name: str
    _type: Type
    layout: LayoutEncoding | None

    array_length_member: str | None
    array_base_member: str | None

    component_type: 'SubstrateType'

    array_length_member: str = 'len'
    array_base_member: str = 'data'

    def __init_subclass__(cls, *, base_specialisation: type | tuple[type] | None = None, **kwargs):
        super().__init_subclass__(**kwargs)

        if not hasattr(cls, 'raw_name'):
            raise TypeError('Expected fixed raw type name for specialisation')

        cls._meta_specialisations[cls.raw_name] = (cls, base_specialisation)

    def __new__(metacls, name, bases, namespace, **_):
        return super().__new__(metacls, name, bases, namespace)

    def register_alias(cls, alias: str):
        SubstrateType._type_registry.setdefault(cls.view, {})[alias] = cls

    def __init__(
        cls,
        name,
        bases,
        namespace,
        *,
        view: BinaryView | SvmHeap,
        raw_type_name: str | None = None,
        type_name: str | None = None,
        _type: Type | None = None
    ):
        super().__init__(name, bases, namespace)

        cls.heap = view if isinstance(view, SvmHeap) else SvmHeap.for_view(view)

        if not hasattr(cls, 'raw_name'):
            if raw_type_name is None:
                raise ValueError('Expected raw_type_name to be specified')

            cls.raw_name = raw_type_name

        if not hasattr(cls, 'name'):
            from . import get_readable_type_name
            cls.name = type_name or get_readable_type_name(cls.raw_name)

        if cls.name != cls.raw_name:
            SubstrateType.register_alias(cls, cls.name)

        from .svm import create_hub_builder
        cls._type = _type
        if (_type := cls.view.get_type_by_name(cls.name)) is not None:
            if cls._type is not None and _type != cls._type:
                cls.view.define_user_type(cls.name, cls._type)
            else:
                cls._type = _type
        if cls._type is None:
            if hasattr(cls, 'make_type_definitions'):
                for name, definition in cls.make_type_definitions(cls.view):
                    if name == cls.name:
                        cls._type = definition
                        break
                else:
                    raise ValueError()
            else:
                cls._type = create_hub_builder(cls.view)
            cls.view.define_user_type(cls.name, cls._type)
            cls._type = cls.view.get_type_by_name(cls.name)

        cls.layout = None

        cls.component_type = None
        cls.array_type = None

    @property
    def view(cls):
        return cls.heap.view

    @property
    def type(cls):
        return cls._type

    @type.setter
    def type(cls, new_type: Type):
        cls.view.define_user_type(cls.name, new_type)
        cls._type = cls.view.get_type_by_name(cls.name)

    @property
    def registered_name(cls):
        return cls._type.registered_name

    def __getitem__(cls, key: str):
        return cls._type[key]

    @property
    def hub_address(cls):
        # HACK
        from .jdk.klass import SubstrateClass
        class_type = SubstrateClass.for_view(cls.heap)
        if not class_type.reconstructed:
            return class_type.lazy_defined_types.get(cls)

        if (attribute := cls.type.attributes.get("LyticEnzyme.Hub", "unknown")) == 'unknown':
            return None

        try:
            return int(attribute, 16)
        except ValueError:
            return None

    @hub_address.setter
    def hub_address(cls, addr: int):
        from .jdk.klass import SubstrateClass
        class_type = SubstrateClass.for_view(cls.heap)

        if cls.hub_address == addr:
            return

        if not class_type.reconstructed:
            if cls in class_type.lazy_defined_types:
                assert class_type.lazy_defined_types[cls] == addr, 'expected to set once'
                return
            
            class_type.lazy_defined_types[cls] = addr
            return

        assert cls.hub_address is None, 'expected to set once'

        class_struct = cls.type.mutable_copy()
        class_struct.attributes['LyticEnzyme.Hub'] = hex(addr)
        cls.type = class_struct

        cls.view.define_data_var(
            addr,
            class_type.derive_type(addr),
            cls.name + '.class',
        )
        SubstrateType.get_hub_mapping(cls.view)[addr] = cls

        hub_accessor = class_type.typed_data_accessor(addr)

        component_hub_ptr = hub_accessor['componentType'].value
        if component_hub_ptr != 0 and (component_hub := cls.heap.resolve_target(component_hub_ptr)) is not None:
            cls.component_type = SubstrateType.from_hub(cls.heap, component_hub)

        if cls.layout is None:
            cls._update_layout(
                layout_encoding=LayoutEncoding.parse(hub_accessor['layoutEncoding'].value),
                id_hash_offset=hub_accessor['identityHashOffset'].value,
                monitor_offset=hub_accessor['monitorOffset'].value,
            )
        
        if (companion := cls.heap.resolve_target(hub_accessor['companion'].value)) is not None:
            companion_accessor = cls.view.typed_data_accessor(
                companion,
                cls.view.get_type_by_name('com.oracle.svm.core.hub.DynamicHubCompanion')
            )

            array_hub_ptr = companion_accessor['arrayHub'].value
            if array_hub_ptr != 0 and (array_hub := cls.heap.resolve_target(array_hub_ptr)) is not None:
                cls.array_type = SubstrateType.from_hub(cls.heap, array_hub)

    _id_hash_code_offset_override: int | None

    @property
    def is_simple_array(cls):
        if cls.layout is None:
            return False

        if not cls.layout.is_object_array and not cls.layout.is_primitive_array:
            return False

        try:
            id_hash_code_offset = cls['identityHashCode'].offset
        except:
            id_hash_code_offset = getattr(cls, '_id_hash_code_offset_override', None)

        if id_hash_code_offset != cls.heap.address_size:
            return False
        
        if cls.layout.array_base_offset != cls.heap.address_size + 4 + 4:
            return False

        return True

    def _update_layout(
        cls,
        layout_encoding: LayoutEncoding,
        id_hash_offset: int | None = None,
        monitor_offset: int | None = None,
    ):
        from .jdk.object import make_object_ptr

        cls.layout = layout_encoding

        # Should remain invariant
        if cls.layout.is_primitive or cls.name == 'java.lang.Object':
            return

        type_changed = False
        class_type_builder = cls.type.mutable_copy()

        if not cls.layout.is_special:
            old_id_hash_offset = None
            try:
                old_id_hash_offset = cls['identityHashCode']
            except ValueError:
                pass

            if id_hash_offset is not None and old_id_hash_offset is None:
                if id_hash_offset != 0 and id_hash_offset >= cls.heap.address_size:
                    class_type_builder.add_member_at_offset('identityHashCode', Type.int(4, True), id_hash_offset, False)
                    cls._id_hash_code_offset_override = id_hash_offset
                    type_changed = True
            else:
                id_hash_offset = old_id_hash_offset

            if monitor_offset:
                try:
                    cls['$monitor']
                except ValueError:
                    class_type_builder.add_member_at_offset(
                        '$monitor',
                        make_object_ptr(cls.view, 'com.oracle.svm.core.monitor.JavaMonitor'),
                        monitor_offset,
                        overwrite_existing=False,
                    )
                    type_changed = True

        if cls.layout.is_pure_instance and class_type_builder.width < layout_encoding.instance_size:
            class_type_builder.width = cls.layout.instance_size
            type_changed = True
        elif cls.layout.is_array_like:
            base_offset = cls.layout.array_base_offset
            if class_type_builder.width < base_offset:
                class_type_builder.width = base_offset
                type_changed = True

            if cls.is_simple_array:
                assert id_hash_offset is not None, 'value arrays must have an identityHashCode'

                class_type_builder.add_member_at_offset(
                    cls.array_length_member,
                    TypeBuilder.int(4, True),
                    id_hash_offset + 4,
                )

                if cls.component_type:
                    element_type = cls.component_type.registered_name
                    if not cls.component_type.layout.is_primitive:
                        element_type = (
                            TypeBuilder.pointer(
                                cls.view.arch,
                                cls.component_type.registered_name
                            )
                        )
                elif cls.layout.is_primitive_array:
                    element_type = TypeBuilder.int(
                        cls.layout.array_index_scale
                    )
                elif cls.layout.is_object_array:
                    element_type = make_object_ptr(cls.view, 'java.lang.Object')

                class_type_builder.add_member_at_offset(
                    cls.array_base_member,
                    TypeBuilder.array(
                        element_type,
                        1,
                    ),
                    base_offset,
                )
                cls.array_length_member = 'len'
                cls.array_base_member = 'data'

                type_changed = True

        if hasattr(cls, '_id_hash_code_offset_override'):
            delattr(cls, '_id_hash_code_offset_override')

        if type_changed:
            cls.type = class_type_builder
    
    def _is_instance(cls, addr: int, **kwargs) -> bool:
        if (data_var := cls.view.get_data_var_at(addr)) and data_var.type == cls.type:
            return True
        
        if (hub_addr := cls.heap.read_pointer(addr)) == cls.hub_address:
            return True
        
        from .jdk.klass import SubstrateClass
        return SubstrateClass.for_view(cls.view).is_instance(hub_addr, cls.raw_name, **kwargs)

    def is_instance(cls, addr: int, **kwargs) -> bool:
        return cls._is_instance(addr, **kwargs)
    
    def typed_data_accessor(cls, addr: int) -> TypedDataAccessor:
        return cls.view.typed_data_accessor(addr, cls.type)

    def find_hub(cls):
        if cls.hub_address is not None:
            return True

        from .jdk.klass import SubstrateClass
        hub = SubstrateClass.for_view(cls.heap).find_by_name(cls.raw_name)
        if not hub:
            return False
        
        cls.hub_address = hub

        return True

    def find_instances(cls):
        if not (hub := cls.hub_address):
            return
        
        yield from cls.heap.find_refs_to(hub)

    def derive_type(cls, addr: int):
        accessor = cls.typed_data_accessor(addr)
        data_len = accessor[cls.array_length_member].value

        derived_type = TypeBuilder.class_type()
        derived_type.base_structures = [
            BaseStructure(
                Type.named_type_from_type(cls.name, cls.type),
                0,
                width=cls.type[cls.array_base_member].offset if data_len == 0 else 0
            ),
        ]
        derived_type.add_member_at_offset(
            cls.array_base_member,
            TypeBuilder.array(
                cls.type[cls.array_base_member].type.element_type,
                data_len,
            ),
            cls.type[cls.array_base_member].offset
        )
        
        return derived_type

    def references_from(cls, addr: int):
        from ..types import is_pointer_to_java_type

        for inherited_member in cls.type.members_including_inherited(cls.view):
            member = inherited_member.member
            offset = inherited_member.base_offset + member.offset
            if member.name == 'hub' and offset == 0:
                continue

            if not is_pointer_to_java_type(cls.view, member.type):
                continue

            if (target := cls.heap.read_pointer(addr + offset)) is None:
                continue

            yield target

        if cls.layout.has_object_elements and cls.array_base_member:
            if not is_pointer_to_java_type(
                cls.view,
                element_type := cls.type[cls.array_base_member].type.element_type,
            ):
                return

            for ptr in cls.view.typed_data_accessor(
                addr + cls.type[cls.array_base_member].offset,
                Type.array(
                    element_type,
                    cls.typed_data_accessor(addr)[cls.array_length_member].value,
                )
            ):
                if (ref := cls.heap.resolve_target(ptr.value)) is not None:
                    yield ref

    @staticmethod
    def from_hub(heap: SvmHeap, hub: int):
        from .jdk.klass import SubstrateClass
        try:
            return SubstrateClass.for_view(heap)(hub).instance_type
        except ValueError:
            return None

    @staticmethod
    def by_name(view_or_heap: BinaryView | SvmHeap, raw_type_name: str, type_name: str | None = None, *, find_hub = False):
        stype = new_class(
            name=f"SubstrateType<{raw_type_name}>",
            kwds={
                "metaclass": SubstrateType,
                "view": view_or_heap,
                "raw_type_name": raw_type_name,
                "type_name": type_name,
            },
        )
        if find_hub:
            stype.find_hub()

        return stype

class ManagedHeapObject:
    _object_registry: dict[SubstrateType, dict[int, object]] = {}

    def __call__(cls, address: int, *args, **kwargs):
        if address not in (objects := cls._object_registry.setdefault(cls, {})):
            objects[address] = super(ManagedHeapObject, cls).__call__(address, *args, **kwargs)

        return objects[address]