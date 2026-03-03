from binaryninja import BinaryView, TypedDataAccessor
from binaryninja.types import Type as BNType, TypeBuilder, StructureType, StructureBuilder, StructureMember, BaseStructure, ArrayType, QualifiedName

from types import new_class
from typing import ClassVar, Self, Iterator, Type, TypeAlias, cast
from abc import abstractmethod
from functools import wraps

from ..heap import SvmHeap, SvmHeapAccessor
from .builder import ObjectBuilder
from .layout_encoding import LayoutEncoding, LayoutType, PureInstanceLayout, ArrayLikeLayout
from .builder import LyticTypeBuilder

RawTypeName: TypeAlias = str # Name as encoded in metadata
ReadableTypeName: TypeAlias = str # Readable name as registered in types

class SubstrateTypeMeta(type):
    _type_registry: dict[BinaryView, dict[RawTypeName, '_SubstrateEigenType']] = {}
    _type_name_aliases: dict[ReadableTypeName, RawTypeName] = {}
    _base_specialisations: dict[RawTypeName, '_SubstrateEigenType'] = {}

    def __call__(cls, name, bases, *args, view: BinaryView | SvmHeap | None = None, **kwargs):
        if view is None:
            return super(SubstrateTypeMeta, cls).__call__(name, bases, *args, view=None, *kwargs)

        instances = cls._type_registry.setdefault(
            view if isinstance(view, BinaryView) else view.view,
            {}
        )
        if (type_name := getattr(cls, 'raw_name', kwargs.get('raw_type_name'))) is None:
            raise TypeError('Could not resolve name')
        if not isinstance(type_name, str):
            raise TypeError('Unexpected type for name')

        raw_type_name = cls._type_name_aliases.get(type_name, type_name)

        if raw_type_name not in instances:
            abc_base: _SubstrateEigenType = SubstrateType
            if raw_type_name in cls._base_specialisations:
                abc_base = cls._base_specialisations[raw_type_name]
                name = abc_base.__name__
            instances[raw_type_name] = instance = super(
                SubstrateTypeMeta,
                cls,
            ).__call__(
                name,
                (*bases, abc_base),
                *args,
                view=view,
                **kwargs
            )

            if instance.name != instance.raw_name:
                SubstrateTypeMeta.register_alias(instance.raw_name, instance.name)

            return instance

        return instances[raw_type_name]

    @staticmethod
    def register_alias(name: RawTypeName, alias: ReadableTypeName):
        assert SubstrateTypeMeta._type_name_aliases.get(alias, name) == name
        SubstrateTypeMeta._type_name_aliases[alias] = name

    @staticmethod
    def register_specialisation(raw_name: RawTypeName, specialisation: '_SubstrateEigenType'):
        SubstrateTypeMeta._base_specialisations[raw_name] = specialisation

class _SubstrateEigenType(type, metaclass=SubstrateTypeMeta):
    raw_name: RawTypeName
    name: ReadableTypeName

    heap: SvmHeap

    layout: LayoutEncoding | None
    component_type: Type['SubstrateType'] | None
    array_type: Type['SubstrateType'] | None

    array_length_member: str = 'len'
    array_base_member: str = 'data'

    auto_offsets: set[int]

    @staticmethod
    @abstractmethod
    def make_type_definitions(view: BinaryView) -> list[LyticTypeBuilder]: ...

    def __new__(mcs, name, bases, namespace, **_):
        return super().__new__(mcs, name, bases, namespace)

    def __init__(
        cls,
        *args,
        view: BinaryView | SvmHeap | None = None,
        raw_type_name: RawTypeName | None = None,
        type_name: ReadableTypeName | None = None,
        _type: BNType | None = None
    ):
        super().__init__(*args)

        if view is None:
            return

        cls.heap = view if isinstance(view, SvmHeap) else SvmHeap.for_view(view)

        if not hasattr(cls, 'raw_name'):
            if raw_type_name is None:
                raise ValueError('Expected raw_type_name to be specified')

            cls.raw_name = raw_type_name

        if not hasattr(cls, 'name'):
            from . import get_readable_type_name
            cls.name = type_name or get_readable_type_name(cls.raw_name)

        if (predefined := cls.view.get_type_by_name(cls.name)) is not None:
            if _type is None:
                _type = predefined
            elif predefined != _type:
                cls.view.define_user_type(cls.name, _type)

        if _type is None:
            if not getattr((factory := cls.make_type_definitions), '__isabstractmethod__', True):
                for definition in factory(cls.view):
                    if isinstance(definition, tuple):
                        type_name, definition = definition
                    else:
                        type_name = str(definition.name)

                    if type_name == cls.name:
                        _type = definition.immutable_copy()
                    break
            else:
                _type = ObjectBuilder(cls.view, cls.name).immutable_copy()

            if _type is None:
                raise ValueError()

        cls.type = _type

        cls.layout = None

        cls.component_type = None
        cls.array_type = None

        cls.auto_offsets = set()

        cls.__type_init__()

    @classmethod
    def __type_init__(cls):
        pass

    _object_registry: ClassVar[dict['_SubstrateEigenType', dict[int, 'SubstrateType']]] = {}
    def __call__(cls, address: int, *args, view: SvmHeap | BinaryView | None = None, **kwargs):
        if view is not None:
            cls = cls.for_view(view)
        elif cls.view is None:
            raise TypeError

        if address not in (objects := cls._object_registry.setdefault(cls, {})):
            objects[address] = super().__call__(address, *args, **kwargs)

        return objects[address]

    @property
    def view(self):
        return self.heap.view

    _type: BNType

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, new_type: BNType | TypeBuilder):
        self.view.define_user_type(self.name, new_type)
        _type = self.view.get_type_by_name(self.name)
        assert _type is not None
        self._type = _type

    def __getitem__(cls, key: str) -> StructureMember:
        assert isinstance(cls.type, StructureType)

        if (member := cls.type[key]) is None:
            raise KeyError

        return member

    def update_layout(
        cls,
        layout_encoding: LayoutEncoding,
        id_hash_offset: int | None = None,
        monitor_offset: int | None = None,
    ):
        assert cls.view.arch is not None

        cls.layout = layout_encoding

        # Should remain invariant
        if (cls.layout.is_special and cls.layout.layout_type != LayoutType.ABSTRACT) or cls.name == 'java.lang.Object':
            return

        type_changed = False
        instance_type_builder = cls.type.mutable_copy()
        if not cls.layout.is_special:
            assert isinstance(cls.type, StructureType)
            assert isinstance(instance_type_builder, StructureBuilder)
            old_id_hash_offset = next(
                (
                    m.offset
                    for m in cls.type.members
                    if m.name == 'identityHashCode'
                ),
                None,
            )

            if id_hash_offset is not None and old_id_hash_offset is None:
                if id_hash_offset != 0 and id_hash_offset >= cls.heap.address_size:
                    instance_type_builder.add_member_at_offset('identityHashCode', BNType.int(4, True), id_hash_offset, False)
                    cls._id_hash_code_offset_override = id_hash_offset
                    type_changed = True
            else:
                id_hash_offset = old_id_hash_offset

            if monitor_offset and next((m for m in cls.type.members if m.name == '$monitor'), None) is None:
                instance_type_builder.add_member_at_offset(
                    '$monitor',
                    ObjectBuilder.object_pointer(
                        cls.view,
                        'com.oracle.svm.core.monitor.JavaMonitor',
                    ),
                    monitor_offset,
                    overwrite_existing=False,
                )
                type_changed = True

        if isinstance(cls.layout, PureInstanceLayout) and instance_type_builder.width < cls.layout.instance_size:
            instance_type_builder.width = cls.layout.instance_size
            type_changed = True
        elif isinstance(cls.layout, ArrayLikeLayout):
            base_offset = cls.layout.array_base_offset

            if instance_type_builder.width < base_offset:
                instance_type_builder.width = base_offset
                type_changed = True

            if cls.is_simple_array:
                assert isinstance(cls.type, StructureType)
                assert isinstance(instance_type_builder, StructureBuilder)
                assert id_hash_offset is not None, 'value arrays must have an identityHashCode'

                instance_type_builder.add_member_at_offset(
                    cls.array_length_member,
                    TypeBuilder.int(4, True),
                    id_hash_offset + 4,
                )

                element_type = None
                if cls.component_type:
                    element_type = cls.component_type.registered_name
                    if not getattr(cls.component_type.layout, 'is_primitive', False):
                        element_type = BNType.pointer(
                            cls.view.arch,
                            element_type,
                        )
                elif cls.layout.is_primitive_array:
                    element_type = BNType.int(cls.layout.array_index_scale)
                elif cls.layout.is_object_array:
                    element_type = ObjectBuilder.object_pointer(cls.view, 'java.lang.Object')
                else:
                    raise ValueError

                instance_type_builder.add_member_at_offset(
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

        cls._id_hash_code_offset_override = None

        for offset in cls.heap.relative_offsets_by_type(cls.hub_address):
            _type = instance_type_builder.immutable_copy()

            for i in range(cls.heap.address_size):
                try:
                    _type.member_at_offset_including_inherited(cls.view, offset + i)
                    break
                except ValueError:
                    pass
            else:
                instance_type_builder.insert(
                    offset,
                    ObjectBuilder.object_pointer(cls.view, 'java.lang.Object'),
                )
                cls.auto_offsets.add(offset)
                type_changed = True

        if type_changed:
            cls.type = instance_type_builder.immutable_copy()

    @property
    def registered_name(self):
        ref = self._type.registered_name
        assert ref is not None
        return ref

    @property
    def hub_address(cls) -> int | None:
        # HACK
        from .jdk.klass import SubstrateClass
        class_type = SubstrateClass.for_view(cls.heap)
        if not class_type.reconstructed:
            return class_type.lazy_defined_types.get(cast(Type[SubstrateType], cls))

        if (attribute := cls.type.attributes.get("LyticEnzyme.Hub", "unknown")) == 'unknown':
            return None

        try:
            return int(attribute, 16)
        except ValueError:
            return None

    @hub_address.setter
    def hub_address(cls, addr: int | None):
        if addr is None:
            raise ValueError

        from .jdk.klass import SubstrateClass
        class_type = SubstrateClass.for_view(cls.heap)

        if cls.hub_address == addr:
            return

        if not class_type.reconstructed:
            stype = cast(Type[SubstrateType], cls)
            if stype in class_type.lazy_defined_types:
                assert class_type.lazy_defined_types[stype] == addr, 'expected to set once'
                return
            
            class_type.lazy_defined_types[stype] = addr
            return

        assert cls.hub_address is None, 'expected to set once'

        class_struct = cls.type.mutable_copy()
        class_struct.attributes['LyticEnzyme.Hub'] = hex(addr)
        cls.type = class_struct.immutable_copy()

        cls.hub_mapping[addr] = cast(Type[SubstrateType], cls)

        hub_accessor = class_type.typed_data_accessor(addr)

        if (component_hub := cls.heap.resolve_target(hub_accessor['componentType'])) is not None:
            if (component_type := SubstrateType.from_hub(cls.heap, component_hub)) is not None:
                if cls.component_type is None:
                    cls.component_type = component_type
                elif cls.component_type != component_type:
                    raise ValueError

                assert cls.component_type is not None
                # See override in com.oracle.svm.hosted.SVMHost::createHub
                if cls.name != 'com.oracle.svm.core.heap.FillerArray':
                    if cls.component_type.array_type is None:
                        cls.component_type.array_type = cast(Type[SubstrateType], cls)
                    elif cls.component_type.array_type != cls:
                        print(cls.component_type.array_type, cls)
                        raise ValueError

        if cls.layout is None:
            cls.update_layout(
                layout_encoding=LayoutEncoding.parse(int(hub_accessor['layoutEncoding'])),
                id_hash_offset=int(hub_accessor['identityHashOffset']),
                monitor_offset=int(hub_accessor['monitorOffset']),
            )

        if (companion := cls.heap.resolve_target(hub_accessor['companion'])) is not None:
            if (array_hub := cls.heap.resolve_target(SubstrateType.by_name(
                cls.heap,
                'com.oracle.svm.core.hub.DynamicHubCompanion',
            ).typed_data_accessor(companion)['arrayHub'])) is not None:
                if (array_type := SubstrateType.from_hub(cls.heap, array_hub)) is not None:
                    if cls.array_type is None:
                        cls.array_type = array_type
                    elif cls.array_type != array_type:
                        raise ValueError

                    assert cls.array_type is not None
                    if cls.array_type.component_type is None:
                        cls.array_type.component_type = cast(Type[SubstrateType], cls)
                    elif cls.array_type.component_type != cls:
                        raise ValueError

    _hub_mappings: ClassVar[dict[BinaryView, dict[int, Type['SubstrateType']]]] = {}

    @property
    def hub_mapping(self):
        return self._hub_mappings.setdefault(self.view, {})

class IsSimpleArrayDescriptor:
    def __get__(self, _, cls: Type['SubstrateType']) -> bool:
        if not isinstance(cls.layout, ArrayLikeLayout):
            return False

        if not cls.layout.is_object_array and not cls.layout.is_primitive_array:
            return False

        try:
            id_hash_code_offset = cls['identityHashCode'].offset
        except:
            id_hash_code_offset = cls._id_hash_code_offset_override

        if id_hash_code_offset != cls.heap.address_size:
            return False

        if cls.layout.array_base_offset != cls.heap.address_size + 4 + 4:
            return False

        return True

def typemethod(func):
    @wraps(func)
    def wrapper(cls: Type['SubstrateType'], *args, view: SvmHeap | BinaryView | None = None, **kwargs):
        if view is not None:
            cls = cls.for_view(view)
        elif cls.view is None:
            raise TypeError
        
        return func(cls, *args, **kwargs)
    
    return wrapper

class SubstrateType(metaclass=_SubstrateEigenType):
    address: int

    _id_hash_code_offset_override: int | None = None

    is_simple_array: ClassVar[IsSimpleArrayDescriptor] = IsSimpleArrayDescriptor()

    @abstractmethod
    def __init__(self, address: int):
        self.address = address

    def __init_subclass__(cls):
        super().__init_subclass__()

        if (raw_name := getattr(cls, 'raw_name', None)) is not None:
            SubstrateTypeMeta.register_specialisation(raw_name, cls)
            if (name := getattr(cls, 'name', None)) is not None:
                SubstrateTypeMeta.register_alias(raw_name, name)

    @classmethod
    @typemethod
    def is_instance(cls, addr: int, **kwargs) -> bool:
        from .jdk.klass import SubstrateClass

        if (data_var := cls.view.get_data_var_at(addr)) and data_var.type == cls.type:
            return True
        
        if (hub_addr := cls.heap.read_pointer(addr)) is None:
            return False

        if cls.hub_address is None:
            if not SubstrateClass.is_instance(hub_addr, cls.raw_name, **kwargs, view=cls.heap):
                return False
            
            cls.hub_address = hub_addr

        if hub_addr != cls.hub_address:
            return False

        if cls.layout is None and SubstrateClass.for_view(cls.heap).reconstructed:
            raise ValueError
        
        if not isinstance(cls.layout, ArrayLikeLayout) or not cls.layout.is_object_array:
            return True

        if (component_type := cls.component_type) is None:
            raise ValueError

        # TODO use cls.array_len_member
        if (length := cls.view.read_int(addr + 0xc, 0x4)) == 0:
            return False

        # TODO use cls.array_base_member
        array_start = addr + 0x10
        array_end = array_start + (cls.heap.address_size * length)
        if not (cls.heap.start <= array_end - cls.heap.address_size <= cls.heap.end):
            return False

        for current in range(array_start, array_end, cls.heap.address_size):
            if (ptr := cls.view.read_pointer(current)) == 0:
                continue

            if (element := cls.heap.resolve_target(ptr)) is None:
                return False

            if not component_type.is_instance(element):
                return False

        return True

    @classmethod
    @typemethod
    def define_instance_at(cls, addr: int) -> int | None:
        definite_width = None

        _type = cls.registered_name
        if cls.is_simple_array:
            _type = cls.derive_type(addr)
            definite_width = _type.width
        elif isinstance(cls.layout, PureInstanceLayout):
            definite_width = _type.width

        cls.view.define_user_data_var(addr, _type)

        return definite_width

    @classmethod
    @typemethod
    def typed_data_accessor(cls, addr: int) -> TypedDataAccessor:
        return cls.view.typed_data_accessor(addr, cls.type)

    @classmethod
    @typemethod
    def accessor(cls, addr: int) -> SvmHeapAccessor:
        return cls.heap.accessor(addr, cls.type)

    @classmethod
    @typemethod
    def find_hub(cls) -> bool:
        if cls.hub_address is not None:
            return True

        from .jdk.klass import SubstrateClass
        if not (hub := SubstrateClass.find_by_name(
            cls.raw_name,
            view=cls.heap,
        )):
            return False
        
        cls.hub_address = hub

        return True

    @classmethod
    @typemethod
    def find_instances(cls) -> Iterator[int]:
        if not (hub := cls.hub_address):
            return
        
        for addr in cls.heap.find_refs_to(hub):
            if cls.is_instance(addr):
                yield addr

    @classmethod
    @typemethod
    def derive_type(cls, addr: int) -> StructureBuilder:
        data_len = int(cls.typed_data_accessor(addr)[cls.array_length_member])

        assert isinstance(cls.type, StructureType)

        derived_type = TypeBuilder.class_type()

        array_base_member = cls.type[cls.array_base_member]
        assert isinstance(array_base_member.type, ArrayType)

        derived_type.base_structures = [
            BaseStructure(
                BNType.named_type_from_type(cls.name, cls.type),
                0,
                width=array_base_member.offset if data_len == 0 else 0
            ),
        ]
        derived_type.add_member_at_offset(
            cls.array_base_member,
            TypeBuilder.array(
                array_base_member.type.element_type,
                data_len,
            ),
            array_base_member.offset
        )
        
        return derived_type

    @classmethod
    @typemethod
    def references_from(cls, addr: int) -> Iterator[tuple[int, int]]:
        from . import is_pointer_to_java_type

        if not isinstance(_type := cls.type, StructureType):
            return

        for inherited_member in _type.members_including_inherited(cls.view):
            member = inherited_member.member
            offset = inherited_member.base_offset + member.offset
            if member.name == 'hub' and offset == 0:
                continue

            if not is_pointer_to_java_type(cls.view, member.type):
                continue

            if (target := cls.heap.read_pointer(addr + offset)) is None:
                continue

            yield (addr + offset, target)

        if not isinstance(cls.layout, ArrayLikeLayout) or not cls.layout.has_object_elements:
            return

        if not cls.array_base_member:
            return

        array_base_member = _type[cls.array_base_member]
        assert isinstance(array_base_member.type, ArrayType)

        if not is_pointer_to_java_type(
            cls.view,
            element_type := array_base_member.type.element_type,
        ):
            return

        for ptr in cls.view.typed_data_accessor(
            addr + array_base_member.offset,
            BNType.array(
                element_type,
                int(cls.typed_data_accessor(addr)[cls.array_length_member]),
            )
        ):
            if (ref := cls.heap.resolve_target(ptr)) is not None:
                yield (ptr.address, ref)

    @classmethod
    def for_view(cls, view: BinaryView | SvmHeap) -> Type[Self]:
        return new_class(
            name=cls.__name__,
            kwds={
                'metaclass': _SubstrateEigenType,
                'view': view,
                'raw_type_name': cls.raw_name,
            },
            exec_body=None,
        )

    @staticmethod
    def from_hub(heap: SvmHeap, hub: int) -> Type['SubstrateType'] | None:
        from .jdk.klass import SubstrateClass
        try:
            return SubstrateClass(hub, view=heap).instance_type
        except ValueError:
            return None

    @staticmethod
    def by_name(view_or_heap: BinaryView | SvmHeap, raw_type_name: RawTypeName, type_name: ReadableTypeName | None = None, *, find_hub = False) -> Type['SubstrateType']:
        stype = cast(Type[SubstrateType], new_class(
            name=f"SubstrateType<{raw_type_name}>",
            kwds={
                "metaclass": _SubstrateEigenType,
                "view": view_or_heap,
                "raw_type_name": raw_type_name,
                "type_name": type_name,
            },
        ))
        if find_hub:
            stype.find_hub()

        return stype
