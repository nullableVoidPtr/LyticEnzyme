from binaryninja import BinaryView, Component
from binaryninja.types import Type as BNType, TypeBuilder, StructureType, StructureBuilder, NamedTypeReferenceType, EnumerationBuilder, BaseStructure, Symbol
from binaryninja.architecture import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, NamedTypeReferenceClass, SymbolType

from typing import ClassVar, Type, Final
from enum import IntEnum, IntFlag, auto
from functools import cached_property

from ....heap import SvmHeapAccessor
from ....component import LazyComponent
from ...meta import SubstrateType, _SubstrateEigenType, typemethod
from ...builder import ObjectBuilder, EnumBuilder
from ..reflect import ReflectionModifiers

class AccessModifier(IntEnum):
    PUBLIC = auto()
    PRIVATE = auto()
    PROTECTED = auto()

class InheritanceModifier(IntEnum):
    NONE = auto()
    ABSTRACT = auto()
    FINAL = auto()

class ClassType(IntEnum):
    PRIMITIVE = auto()
    CLASS = auto()
    INTERFACE = auto()
    RECORD = auto()
    LAMBDA = auto()

class DynamicHubFlags(IntFlag):
    IS_PRIMITIVE = auto()
    IS_INTERFACE = auto()
    IS_HIDDEN = auto()
    IS_RECORD = auto()
    RUNTIME_ASSERTED = auto()
    HAS_DEFAULT_METHODS = auto()
    DECLARES_DEFAULT_METHODS = auto()
    IS_SEALED = auto()
    IS_VM_INTERNAL = auto()
    IS_LAMBDA_FORM_HIDDEN = auto()
    IS_LINKED = auto()
    IS_PROXY_CLASS = auto()

class SubstrateVTable:
    klass: 'SubstrateClass'
    funcs: list[int]
    names: list[str | None]
    type: BNType

    def __init__(self, klass: 'SubstrateClass'):
        self.klass = klass

        class_type = type(self.klass)
        vtable_start = self.klass.address + class_type['vtable'].offset
        accessor = class_type.typed_data_accessor(self.klass.address)

        self.funcs = [
            self.view.read_pointer(i)
            for i in range(
                vtable_start,
                vtable_start + (int(accessor['vtableLength']) * self.view.arch.address_size),
                self.view.arch.address_size,
            )
        ]

        self.names = [None for _ in range(len(self))]
        self.update_type()

    def __setitem__(self, key: int, name: str):
        self.names[key] = name

    def update_type(self):
        vtable_type_name = f"{self.klass.type_name}$$VTable"
        self.view.define_user_type(
            vtable_type_name,
            StructureBuilder.create(members=[
                (TypeBuilder.named_type_reference(
                    NamedTypeReferenceClass.TypedefNamedTypeClass,
                    'org.graalvm.nativeimage.c.function.CFunctionPointer',
                    alignment=self.view.arch.address_size,
                    width=self.view.arch.address_size,
                ), name or f"$method{i}")
                for i, name in enumerate(self.names)
            ]),
        )
        self.type = self.view.get_type_by_name(vtable_type_name)

    @property
    def registered_name(self) -> NamedTypeReferenceType:
        return self.type.registered_name

    @property
    def view(self) -> BinaryView:
        return type(self.klass).view

    def __len__(self) -> int:
        return len(self.funcs)

PRIMITIVE_NAMES = {
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

class SubstrateClass(SubstrateType):
    raw_name = 'java.lang.Class'

    array_length_member = 'vtableLength'
    array_base_member = 'vtable'

    reconstructed: ClassVar[bool]
    lazy_defined_types: ClassVar[dict[_SubstrateEigenType, int]] = {}

    @classmethod
    def __type_init__(cls):
        assert isinstance(cls.type, StructureType)
        cls.reconstructed = any(m.name == 'layoutEncoding' for m in cls.type.members)

    @staticmethod
    def make_type_definitions(view: BinaryView):
        flags_enum = EnumBuilder(
            view,
            DynamicHubFlags.__name__,
            DynamicHubFlags,
            width=2,
        )

        class_struct = ObjectBuilder(view, 'java.lang.Class', members=[
            (TypeBuilder.int(4, True), 'identityHashCode'),
            (TypeBuilder.int(4, True), 'vtableLength'),
        ])
        # class_struct.append(TypeBuilder.array(TypeBuilder.int(2, True), 0xa), 'closedTypeWorldTypeCheckSlots')
        # class_struct.append(TypeBuilder.int(2, True), 'field_12')
        # class_struct.append(TypeBuilder.int(2, True), 'field_14')
        # class_struct.append(TypeBuilder.int(2, True), 'field_16')
        # class_struct.append(TypeBuilder.int(2, True), 'field_18')
        # class_struct.add_member_at_offset('monitorOffset', TypeBuilder.char(), 0x26)
        # class_struct.append(make_object_ptr(view, 'java.lang.String'), 'name')
        # class_struct.append(make_object_ptr(view, 'java.lang.Class'), 'componentType')
        # class_struct.append(make_object_ptr(view, 'com.oracle.svm.core.hub.DynamicHubCompanion'), 'companion')
        # class_struct.append(TypeBuilder.int(4, True), 'layoutEncoding')
        # class_struct.append(TypeBuilder.int(4, True), 'referenceMapIndex')
        # class_struct.append(TypeBuilder.char(), 'identityHashOffset')
        # class_struct.append(TypeBuilder.int(2, True), 'typeCheckStart')
        # class_struct.append(TypeBuilder.int(2, True), 'typeCheckRange')
        # class_struct.append(TypeBuilder.int(2, True), 'typeCheckSlot')
        # class_struct.append(TypeBuilder.int(2, True), 'flags')
        # class_struct.append(TypeBuilder.char(), 'hubType')
        # class_struct.append(TypeBuilder.char(), 'layerId')
        # vtable_type = TypeBuilder.array(
        #     TypeBuilder.named_type_reference(
        #         NamedTypeReferenceClass.TypedefNamedTypeClass,
        #         'org.graalvm.nativeimage.c.function.CFunctionPointer',
        #         alignment=view.arch.address_size,
        #         width=view.arch.address_size,
        #     ),
        #     1,
        # )
        # class_struct.append(vtable_type, 'vtable')

        return [
            flags_enum,
            class_struct,
        ]

    @classmethod
    def reconstruct_type(cls, class_hub_addr: int):
        from .reconstruct import reconstruct_hub_type
        reconstructed = reconstruct_hub_type(cls.heap, class_hub_addr)
        cls.type = reconstructed.immutable_copy()
        cls.hub_address = class_hub_addr

        cls.reconstructed = True
        for stype, addr in cls.lazy_defined_types.items():
            stype.hub_address = addr

        cls.lazy_defined_types = {}

    @classmethod
    @typemethod
    def is_instance(cls, addr: int, name: str | None = None, **kwargs) -> bool:
        if (metaclass_hub_addr := cls.heap.read_pointer(addr)) is None:
            return False

        expected_metaclass_hub_addr = cls.hub_address

        if expected_metaclass_hub_addr is None:
            if name == 'java.lang.Class':
                if metaclass_hub_addr != addr:
                    return False
            elif not cls.is_instance(metaclass_hub_addr, 'java.lang.Class', **kwargs):
                return False

            if not (metaclass_var := cls.heap.view.get_data_var_at(metaclass_hub_addr)) or metaclass_var.type != cls.type:
                cls.hub_address = metaclass_hub_addr
        elif metaclass_hub_addr != expected_metaclass_hub_addr:
            return False

        from ..string import SubstrateString
        if cls.reconstructed:
            hub_accessor = cls.typed_data_accessor(addr)
            string = cls.heap.resolve_target(hub_accessor['name'])
        else:
            for offset in range(0, 0x100, cls.heap.address_size):
                if (string := cls.heap.read_pointer(addr + offset)) is None:
                    continue

                if (expected_string_hub := cls.heap.read_pointer(string)) is None:
                    continue

                if (name_of_string := cls.heap.read_pointer(expected_string_hub + offset)) is None:
                    continue
                
                if cls.heap.read_pointer(name_of_string) != expected_string_hub:
                    continue

                try:
                    value = SubstrateString.read_unchecked(name_of_string, view=cls.heap)
                    if value != 'java.lang.String':
                        continue
                except ValueError:
                    continue

                class_type = cls.type.mutable_copy()
                assert isinstance(class_type, StructureBuilder)
                class_type.add_member_at_offset(
                    'name',
                    ObjectBuilder.object_pointer(
                        cls.view,
                        'java.lang.String',
                    ),
                    offset,
                )
                cls.type = class_type.immutable_copy()
                break
            else:
                raise ValueError()

        assert string is not None
        if cls is None or not SubstrateString.is_instance(
            string,
            name,
            **{
                **kwargs,
                'expected_string_hub_addr': kwargs.get('expected_string_hub_addr') if name != 'java.lang.String' else addr,
                'expected_byte_array_hub_addr': kwargs.get('expected_byte_array_hub_addr') if name != '[B' else addr,
            },
            view=cls.heap,
        ):
            return False

        if name is not None:
            if name in ['java.lang.String', '[B'] and (stype := SubstrateType.by_name(cls.heap, name)).hub_address is None:
                stype.hub_address = addr

        return True

    @classmethod
    @typemethod
    def find_by_name(cls, name: str) -> int | None:
        from ..string import SubstrateString
        for string in SubstrateString.find_by_value(name, view=cls.heap):
            for addr in cls.heap.find_refs_to(string):
                if cls.is_instance(hub := addr - cls['name'].offset, name):
                    SubstrateType.by_name(cls.view, name).hub_address = hub
                    return hub
        
        return None

    instance_type: Type[SubstrateType]
    name: Final[str]
    type: BNType
    vtable: SubstrateVTable
    superclass: 'SubstrateClass'
    declaring_class: 'SubstrateClass'

    def __init__(self, address: int):
        cls = type(self)

        if not cls.reconstructed:
            raise TypeError

        self.address = address

        accessor = cls.typed_data_accessor(self.address)

        if self.address in (hub_mapping := cls.hub_mapping):
            self.instance_type = hub_mapping[self.address]
        else:
            from ..string import SubstrateString
            if (name := SubstrateString.read(cls.heap.resolve_target(accessor['name']), view=cls.heap)) is None:
                raise ValueError
            
            self.instance_type = SubstrateType.by_name(cls.heap, name)

        self.instance_type.hub_address = self.address

        self.name = self.instance_type.name
        if self.name in PRIMITIVE_NAMES:
            self.name = PRIMITIVE_NAMES[self.name]

        self.vtable = SubstrateVTable(self)

        self.superclass = None
        self.declaring_class = None
        if (companion := self.companion) is not None:
            if (super_hub := cls.heap.resolve_target(companion['superHub'])) is not None:
                self.superclass = cls(super_hub) if super_hub != address else self
            if (declaring_class_hub := cls.heap.resolve_target(companion['declaringClass'])) is not None and cls.is_instance(declaring_class_hub):
                self.declaring_class = cls(declaring_class_hub) if declaring_class_hub != address else self

    @classmethod
    @typemethod
    def define_instance_at(cls, addr: int) -> int:
        klass = cls(addr)

        array_base_member = cls.type[cls.array_base_member]
        _type = TypeBuilder.class_type()
        _type.base_structures = [
            BaseStructure(
                cls.registered_name,
                offset=0,
                width=array_base_member.offset,
            ),
            # BaseStructure(
            #     klass.vtable.registered_name,
            #     offset=array_base_member.offset,
            #     width=klass.vtable.type.width,
            # )
        ]
        _type.append(
            klass.vtable.registered_name,
            "vtable",
        )

        assert cls.hub_address is not None
        _type.attributes['LyticEnzyme.Hub'] = hex(cls.hub_address) or 'unknown'

        cls.view.define_user_type(
            klass.type_name,
            _type,
        )

        cls.view.define_user_data_var(
            addr,
            BNType.named_type_from_registered_type(
                cls.view,
                klass.type_name,
            ),
        )

    def fixup(self, component: LazyComponent | Component | None = None):
        if self.is_enum:
            self._define_enums(component=component)

    def _define_enums(self, component: LazyComponent | Component | None = None):
        cls = type(self)

        # TODO: remove this once superclass structuring is done
        enum_type = SubstrateType.by_name(cls.heap, 'java.lang.Enum')
        struct_builder = self.instance_type.type.mutable_copy()
        assert isinstance(struct_builder, StructureBuilder)
        struct_builder.base_structures = [
            BaseStructure(
                enum_type.registered_name,
                0,
            )
        ]
        struct_builder.width = max(struct_builder.width, enum_type.type.width)

        for i in range(enum_type.type.width):
            if (index := struct_builder.index_by_offset(i)) is not None:
                struct_builder.remove(index)

        self.instance_type.type = struct_builder.immutable_copy()

        if (companion := self.companion) is None:
            return

        if (enum_array := cls.heap.resolve_target(companion['enumConstantsReference'])) is None:
            return

        if (enum_array_hub := cls.heap.read_pointer(enum_array)) is None:
            raise ValueError

        if not (enum_array_type := SubstrateType.from_hub(
            cls.heap,
            enum_array_hub,
        )) or not enum_array_type.is_simple_array:
            return
        
        enum_array_accessor = cls.view.typed_data_accessor(
            enum_array,
            enum_array_type.derive_type(enum_array).immutable_copy()
        )

        builder = EnumerationBuilder.create(width=4)
        for ptr in enum_array_accessor['data']:
            if (resolved_enum := cls.heap.resolve_target(ptr)) is None:
                raise ValueError

            # if cls.heap.read_pointer(
            #     resolved_enum
            # ) != self.address:
            #     raise ValueError

            enum_accessor = self.instance_type.accessor(resolved_enum)

            if (name := enum_accessor['name'].value) is None:
                raise ValueError

            cls.view.define_user_symbol(
                Symbol(
                    SymbolType.DataSymbol,
                    enum_accessor.address,
                    f"{self.name}.{name}",
                ),
            )

            if component and (var := cls.view.get_data_var_at(enum_accessor.address)):
                component.add_data_variable(var)

            builder.append(
                name,
                int(enum_accessor['ordinal']),
            )

        cls.view.define_user_type(
            f"{self.name}.$Ordinal",
            builder.immutable_copy(),
        )

    @property
    def companion(self) -> SvmHeapAccessor | None:
        cls = type(self)

        if (companion := cls.heap.resolve_target(cls.typed_data_accessor(self.address)['companion'])) is None:
            return None

        return SubstrateType.by_name(
            cls.heap,
            'com.oracle.svm.core.hub.DynamicHubCompanion',
        ).accessor(companion)

    @cached_property
    def is_enum(self) -> bool:
        if not self.superclass:
            return False

        return self.superclass.name == 'java.lang.Enum'

    @cached_property
    def type_name(self) -> str:
        return f"{type(self).raw_name}<{self.name}>"

    @cached_property
    def flags(self) -> DynamicHubFlags:
        return DynamicHubFlags(int(type(self).typed_data_accessor(self.address)['flags']))

    @cached_property
    def modifiers(self) -> ReflectionModifiers:
        cls = type(self)
        
        companion_addr = cls.heap.resolve_target(cls.typed_data_accessor(self.address)['companion'])
        assert companion_addr is not None

        return ReflectionModifiers(
            int(SubstrateType.by_name(cls.heap, 'com.oracle.svm.core.hub.DynamicHubCompanion').typed_data_accessor(
                companion_addr,
            )['modifiers']),
        )

    @cached_property
    def class_type(self) -> ClassType:
        if DynamicHubFlags.IS_PRIMITIVE in self.flags:
            return ClassType.PRIMITIVE
        elif DynamicHubFlags.IS_INTERFACE in self.flags:
            return ClassType.INTERFACE
        elif DynamicHubFlags.IS_LAMBDA_FORM_HIDDEN in self.flags:
            return ClassType.LAMBDA

        return ClassType.CLASS

    @property
    def access_modifier(self) -> AccessModifier | None:
        if ReflectionModifiers.PUBLIC in self.modifiers:
            return AccessModifier.PUBLIC
        elif ReflectionModifiers.PRIVATE in self.modifiers:
            return AccessModifier.PRIVATE
        elif ReflectionModifiers.PROTECTED in self.modifiers:
            return AccessModifier.PROTECTED
        
        return None

    @property
    def inheritance_modifier(self) -> InheritanceModifier:
        if ReflectionModifiers.ABSTRACT in self.modifiers:
            return InheritanceModifier.ABSTRACT
        elif ReflectionModifiers.FINAL in self.modifiers:
            return InheritanceModifier.FINAL

        return InheritanceModifier.NONE
    
    @property
    def sealed(self) -> bool:
        return DynamicHubFlags.IS_SEALED in self.flags
    
    @property
    def hidden(self) -> bool:
        return DynamicHubFlags.IS_HIDDEN in self.flags

    def get_type_tokens_before_name(self):
        tokens = []
        if self.access_modifier:
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.KeywordToken,
                    self.access_modifier.name.lower(),
                ),
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    ' '
                )
            ]


        if ReflectionModifiers.STRICT in self.modifiers:
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.KeywordToken,
                    'strictfp',
                ),
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    ' '
                )
            ]

        if self.inheritance_modifier != InheritanceModifier.NONE:
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.KeywordToken,
                    self.inheritance_modifier.name.lower(),
                ),
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    ' '
                )
            ]

        if self.sealed:
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.KeywordToken,
                    'sealed',
                ),
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    ' '
                )
            ]

        if self.class_type != ClassType.LAMBDA and self.hidden:
            tokens += [
                InstructionTextToken(
                    InstructionTextTokenType.KeywordToken,
                    'hidden',
                ),
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    ' '
                )
            ]

        tokens += [
            InstructionTextToken(
                InstructionTextTokenType.KeywordToken,
                self.class_type.name.lower(),
            ),
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ' '
            )
        ]