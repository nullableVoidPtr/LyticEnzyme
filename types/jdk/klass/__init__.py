from binaryninja import BinaryView, TypedDataAccessor
from binaryninja.types import TypeBuilder, StructureType
from binaryninja.architecture import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

from types import new_class
from typing import Callable
from enum import IntEnum, IntFlag, auto
from functools import cached_property

from ....heap import SvmHeap
from ...meta import SubstrateType, ManagedTypeByAddress
from ...builder import ObjectBuilder, EnumBuilder
from ..reflect import ReflectionModifiers

def accessor_as_int(accessor: TypedDataAccessor | list[TypedDataAccessor]) -> int:
    assert not isinstance(accessor, list)
    return int(accessor)

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

class SubstrateClass:
    heap: SvmHeap # TODO: remove when ABC is defined
    view: BinaryView
    typed_data_accessor: Callable[[int], TypedDataAccessor]

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
    def is_instance(cls, hub_addr: int, name: str | None = None, **kwargs):
        if (metaclass_hub_addr := cls.heap.read_pointer(hub_addr)) is None:
            return False

        expected_metaclass_hub_addr = cls.hub_address

        if expected_metaclass_hub_addr is None:
            if name == 'java.lang.Class':
                if metaclass_hub_addr != hub_addr:
                    return False
            elif not cls.is_instance(metaclass_hub_addr, 'java.lang.Class', **kwargs):
                return False

            if not (metaclass_var := cls.heap.view.get_data_var_at(metaclass_hub_addr)) or metaclass_var.type != cls.type:
                cls.hub_address = metaclass_hub_addr
        elif metaclass_hub_addr != expected_metaclass_hub_addr:
            return False

        from ..string import SubstrateString
        string_type = SubstrateString.for_view(cls.heap)
        if cls.reconstructed:
            hub_accessor = cls.typed_data_accessor(hub_addr)
            string = cls.heap.resolve_target(accessor_as_int(hub_accessor['name']))
        else:
            for offset in range(0, 0x100, cls.heap.address_size):
                if (string := cls.heap.read_pointer(hub_addr + offset)) is None:
                    continue

                if (expected_string_hub := cls.heap.read_pointer(string)) is None:
                    continue

                if (name_of_string := cls.heap.read_pointer(expected_string_hub + offset)) is None:
                    continue
                
                if cls.heap.read_pointer(name_of_string) != expected_string_hub:
                    continue

                try:
                    value = string_type.read_unchecked(name_of_string)
                    if value != 'java.lang.String':
                        continue
                except ValueError:
                    continue

                class_type = cls.type.mutable_copy()
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


        if cls is None or not string_type.is_instance(
            string,
            name,
            **{
                **kwargs,
                'expected_string_hub_addr': kwargs.get('expected_string_hub_addr') if name != 'java.lang.String' else hub_addr,
                'expected_byte_array_hub_addr': kwargs.get('expected_byte_array_hub_addr') if name != '[B' else hub_addr,
            },
        ):
            return False

        if name is not None:
            if name in ['java.lang.String', '[B'] and (stype := SubstrateType.by_name(cls.heap, name)).hub_address is None:
                stype.hub_address = hub_addr

        return True

    @classmethod
    def find_by_name(cls, name: str):
        from ..string import SubstrateString
        for string in SubstrateString.for_view(cls.heap).find_by_value(name):
            for addr in cls.heap.find_refs_to(string):
                if cls.is_instance(hub := addr - cls['name'].offset, name):
                    SubstrateType.by_name(cls.view, name).hub_address = hub
                    return hub

    @staticmethod
    def for_view(view: BinaryView | SvmHeap):
        return new_class(
            name='SubstrateClass',
            kwds={
                'metaclass': SubstrateClassMeta,
                'view': view,
            },
            exec_body=None,
        )
    
    address: int
    instance_type: SubstrateType
    vtable: list

    def __init__(self, address: int):
        cls = type(self)

        if not cls.reconstructed:
            raise TypeError

        self.address = address

        accessor = cls.typed_data_accessor(self.address)

        if self.address in (hub_mapping := SubstrateType.get_hub_mapping(cls.view)):
            self.instance_type = hub_mapping[self.address]
        else:
            if (string := cls.heap.resolve_target(accessor_as_int(accessor['name']))) is None:
                raise ValueError

            from ..string import SubstrateString
            if (name := SubstrateString.for_view(cls.heap).read(string)) is None:
                raise ValueError
            
            self.instance_type = SubstrateType.by_name(cls.heap, name)

        self.instance_type.hub_address = self.address

        self.name = self.instance_type.name

        vtable_start = self.address + cls['vtable'].offset
        self.vtable = [
            cls.view.read_pointer(i)
            for i in range(
                vtable_start,
                vtable_start + (accessor_as_int(accessor['vtableLength']) * cls.heap.address_size),
                cls.heap.address_size
            )
        ]


    @cached_property
    def flags(self) -> DynamicHubFlags:
        return DynamicHubFlags(accessor_as_int(type(self).typed_data_accessor(self.address)['flags']))

    @cached_property
    def modifiers(self) -> ReflectionModifiers:
        cls = type(self)
        
        companion_addr = cls.heap.resolve_target(
            accessor_as_int(cls.typed_data_accessor(self.address)['companion'])
        )
        assert companion_addr is not None

        return ReflectionModifiers(
            accessor_as_int(SubstrateType.by_name(cls.heap, 'com.oracle.svm.core.hub.DynamicHubCompanion').typed_data_accessor(
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

class SubstrateClassMeta(ManagedTypeByAddress, SubstrateType, base_specialisation=SubstrateClass):
    raw_name = 'java.lang.Class'

    array_length_member = 'vtableLength'
    array_base_member = 'vtable'

    reconstructed: bool

    def __init__(cls, *args, **kwargs):
        super().__init__(*args, **kwargs)

        assert isinstance(cls.type, StructureType)
        cls.reconstructed = any(m.name == 'layoutEncoding' for m in cls.type.members)
        cls.lazy_defined_types = {}