from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder, BaseStructure

from types import new_class

from ..heap import SvmHeap
from ..layout_encoding import LayoutEncoding

class SubstrateTypeMeta(type):
    _type_registry: dict[BinaryView, dict[str, 'SubstrateType']] = {}
    _hub_mappings: dict[BinaryView, dict[int, 'SubstrateType']] = {}
    _meta_specialisations: dict[str, 'SubstrateType'] = {}

    def __init__(cls, name, bases, dct):
        super().__init__(name, bases, dct)

        if bases != (type,): # cls != SubstrateType
            if 'raw_name' not in dct:
                raise TypeError('Expected fixed raw type name for specialisation')

            SubstrateTypeMeta._meta_specialisations[dct['raw_name']] = cls

    def __call__(cls, *args, view: BinaryView, **kwargs):
        instances = cls._type_registry.setdefault(view, {})
        if (name := getattr(cls, 'raw_name', kwargs.get('raw_type_name'))) is None:
            raise TypeError('Could not resolve name')

        if name not in instances:
            instances[name] = super(
                SubstrateTypeMeta,
                SubstrateTypeMeta._meta_specialisations.get(name, cls)
            ).__call__(*args, view=view, **kwargs)

        return instances[name]

    def get_hub_mapping(cls, view: BinaryView):
        return cls._hub_mappings.setdefault(view, {})

PRIMITIVE_ALIASES = {
    'jboolean': 'boolean',
    'jbyte': 'byte',
    'jchar': 'char',
    'jshort': 'short',
    'jint': 'int',
    'jlong': 'long',
    'jfloat': 'float',
    'jdouble': 'double',
    'jvoid': 'void',
}

class SubstrateType(type, metaclass=SubstrateTypeMeta):
    view: BinaryView
    raw_name: str
    name: str
    _type: Type
    layout: LayoutEncoding | None

    array_length_member: str | None
    array_base_member: str | None

    component_type: 'SubstrateType'

    def __new__(metacls, name, bases, namespace, **_):
        return super().__new__(metacls, name, bases, namespace)

    def register_alias(cls, alias: str):
        SubstrateType._type_registry.setdefault(cls.view, {})[alias] = cls

    def __init__(cls, name, bases, namespace, *, view: BinaryView, raw_type_name: str | None = None, type_name: str | None = None, _type: Type | None = None):
        super().__init__(name, bases, namespace)

        cls.view = view

        if not hasattr(cls, 'raw_name'):
            if raw_type_name is None:
                raise ValueError('Expected raw_type_name to be specified')

            cls.raw_name = raw_type_name

        if not hasattr(cls, 'name'):
            from . import get_readable_type_name
            cls.name = type_name or get_readable_type_name(cls.raw_name)

        if cls.name in PRIMITIVE_ALIASES:
            cls.name = PRIMITIVE_ALIASES[cls.name]
            SubstrateType.register_alias(cls, cls.name)

        if cls.raw_name.startswith('[') and cls.name.endswith('[]'):
            cls.register_alias(cls.name)

        from .svm import create_hub_builder
        cls._type = _type
        if (_type := view.get_type_by_name(
            cls.name
            if cls.raw_name not in PRIMITIVE_ALIASES else
            cls.raw_name
        )) is not None:
            if cls._type is not None and _type != cls._type:
                cls.view.define_user_type(cls.name, cls._type)
            else:
                cls._type = _type
        if cls._type is None:
            cls._type = getattr(cls, 'make_type_definitions', create_hub_builder)(view)
            cls.view.define_user_type(cls.name, cls._type)

        cls.layout = None

        cls.component_type = None
        if not hasattr(cls, 'array_length_member'):
            cls.array_length_member = None
        if not hasattr(cls, 'array_base_member'):
            cls.array_base_member = None

    def for_view():
        pass

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

    @property
    def hub_address(cls):
        if (attribute := cls.type.attributes.get("LyticEnzyme.Hub", "unknown")) == 'unknown':
            return None

        try:
            return int(attribute, 16)
        except ValueError:
            return None

    @hub_address.setter
    def hub_address(cls, addr: int):
        if cls.hub_address == addr:
            return

        assert cls.hub_address is None, 'expected to set once'

        heap = SvmHeap.for_view(cls.view)

        class_type = cls.type.mutable_copy()
        class_type.attributes['LyticEnzyme.Hub'] = hex(addr)
        cls.type = class_type

        from .jdk.klass import SubstrateClass
        cls.view.define_data_var(
            addr,
            SubstrateClass.for_view(heap.view).derive_type(addr),
            cls.name + '.class',
        )
        SubstrateType.get_hub_mapping(cls.view)[addr] = cls

    @property
    def is_simple_array(cls):
        if cls.layout is None or not cls.layout.is_array_like:
            return False

        try:
            if cls.type['identityHashCode'].offset != cls.view.arch.address_size:
                return False
        except:
            return False

        return cls.layout.array_base_offset == 0x10

    def update_layout(
        cls,
        layout_encoding: LayoutEncoding,
        identity_hash_offset: int | None = None,
    ):
        cls.layout = layout_encoding

        type_changed = False
        class_type_builder = cls.type.mutable_copy()

        if identity_hash_offset is not None and identity_hash_offset != 0 and cls.name != 'java.lang.Object' and not cls.layout.is_primitive:
            try:
                cls.type['identityHashCode']
            except ValueError:
                if identity_hash_offset >= cls.view.get_type_by_name('java.lang.Object').width:
                    class_type_builder.add_member_at_offset('identityHashCode', Type.int(4, True), identity_hash_offset, False)
                    cls.type = class_type_builder

        if cls.layout:
            if cls.layout.is_pure_instance and cls.name != 'java.lang.Object' and class_type_builder.width < layout_encoding.instance_size:
                class_type_builder.width = cls.layout.instance_size
                type_changed = True

            if cls.layout.is_array_like:
                if (min_length := cls.layout.array_base_offset) is not None:
                    if class_type_builder.width < min_length:
                        class_type_builder.width = min_length
                        type_changed = True

                    if cls.component_type:
                        if (cls.layout.is_object_array or cls.layout.is_primitive_array) and cls.is_simple_array:
                            class_type_builder.add_member_at_offset(
                                'len',
                                TypeBuilder.int(4, True),
                                identity_hash_offset + 4,
                            )

                            element_type = (
                                TypeBuilder.pointer(
                                    cls.view.arch,
                                    cls.component_type.registered_name
                                )
                                if not cls.component_type.layout.is_primitive else
                                cls.component_type.registered_name
                            )

                            class_type_builder.add_member_at_offset(
                                'data',
                                TypeBuilder.array(
                                    element_type,
                                    1,
                                ),
                                min_length,
                            )
                            cls.array_length_member = 'len'
                            cls.array_base_member = 'data'

                            type_changed = True

        if type_changed:
            cls.type = class_type_builder

    def derive_type(cls, addr: int):
        heap = SvmHeap.for_view(cls.view)

        accessor = heap.view.typed_data_accessor(addr, cls.type)
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

        heap = SvmHeap.for_view(cls.view)

        for inherited_member in cls.type.members_including_inherited(cls.view):
            member = inherited_member.member
            offset = inherited_member.base_offset + member.offset
            if member.name == 'hub' and offset == 0:
                continue

            if not is_pointer_to_java_type(cls.view, member.type):
                continue

            if (target := heap.read_pointer(addr + offset)) is None:
                continue

            yield target

        if cls.layout.has_object_elements and cls.array_base_member:
            if not is_pointer_to_java_type(
                heap.view,
                element_type := cls.type[cls.array_base_member].type.element_type,
            ):
                return

            for ptr in heap.view.typed_data_accessor(
                addr + cls.type[cls.array_base_member].offset,
                Type.array(
                    element_type,
                    heap.view.typed_data_accessor(addr, cls.type)[cls.array_length_member].value,
                )
            ):
                if (ref := heap.resolve_target(ptr.value)) is not None:
                    yield ref

    @staticmethod
    def from_hub(heap: SvmHeap, hub: int):
        view = heap.view

        from .jdk.klass import SubstrateClass
        hub_accessor = view.typed_data_accessor(hub, SubstrateClass.for_view(view).type)
        
        if hub in (hub_mapping := SubstrateType.get_hub_mapping(view)):
            stype = hub_mapping[hub]
        else:
            if (string := heap.resolve_target(hub_accessor['name'].value)) is None:
                return None

            from .jdk.string import read_string
            if (name := read_string(heap, string)) is None:
                return None
            
            stype = SubstrateType.by_name(heap.view, name)

        if not stype:
            return None

        stype.hub_address = hub

        if (component_hub := heap.resolve_target(hub_accessor['componentType'].value)) is not None:
            stype.component_type = SubstrateType.from_hub(heap, component_hub)

        if stype.layout is None:
            stype.update_layout(
                layout_encoding=LayoutEncoding.parse(hub_accessor['layoutEncoding'].value),
                identity_hash_offset=hub_accessor['identityHashOffset'].value
            )
        
        return stype

    @staticmethod
    def by_name(view: BinaryView, raw_type_name: str, type_name: str | None = None):
        return new_class(
            name=f"SubstrateType<{raw_type_name}>",
            kwds={
                "metaclass": SubstrateType,
                "view": view,
                "raw_type_name": raw_type_name,
                "type_name": type_name,
            },
        )