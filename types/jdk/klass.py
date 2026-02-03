from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder, BaseStructure
from binaryninja.enums import NamedTypeReferenceClass

from types import new_class

from ...heap import SvmHeap
from ..meta import SubstrateType
from ..svm import create_hub_builder
from .object import make_object_ptr

# Klass.make_type_definitions(view)
# create_types registers many SubstrateType after define_user_types
# klass = Klass.for_view(view)
# klass.find_by_name('lol')
# SubstrateType(type)
# KlassMeta(SubstrateType)
# Klass(meta=KlassMeta)

class SubstrateClass:
    def read_raw_name(self):
        pass

    @staticmethod
    def make_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
        class_struct = create_hub_builder(view)
        class_struct.add_member_at_offset('vtableLength', TypeBuilder.int(4, True), 0xc)
        class_struct.append(TypeBuilder.int(2, True), 'typeID')
        class_struct.append(TypeBuilder.int(2, True), 'field_12')
        class_struct.append(TypeBuilder.int(2, True), 'field_14')
        class_struct.append(TypeBuilder.int(2, True), 'field_16')
        class_struct.append(TypeBuilder.int(2, True), 'field_18')
        class_struct.add_member_at_offset('monitorOffset', TypeBuilder.char(), 0x26)
        class_struct.append(make_object_ptr(view, 'java.lang.String'), 'name')
        class_struct.append(make_object_ptr(view, 'java.lang.Class'), 'componentType')
        class_struct.append(make_object_ptr(view, 'com.oracle.svm.core.hub.DynamicHubCompanion'), 'companion')
        class_struct.append(TypeBuilder.int(4, True), 'layoutEncoding')
        class_struct.append(TypeBuilder.int(4, True), 'referenceMapIndex')
        class_struct.append(TypeBuilder.char(), 'identityHashOffset')
        class_struct.append(TypeBuilder.int(2, True), 'typeCheckStart')
        class_struct.append(TypeBuilder.int(2, True), 'typeCheckRange')
        class_struct.append(TypeBuilder.int(2, True), 'typeCheckSlot')
        class_struct.append(TypeBuilder.int(2, True), 'flags')
        class_struct.append(TypeBuilder.char(), 'hubType')
        class_struct.append(TypeBuilder.char(), 'layerId')
        vtable_type = TypeBuilder.array(
            TypeBuilder.named_type_reference(
                NamedTypeReferenceClass.TypedefNamedTypeClass,
                'org.graalvm.nativeimage.c.function.CFunctionPointer',
                alignment=view.arch.address_size,
                width=view.arch.address_size,
            ),
            1,
        )
        vtable_type.attributes['LyticEnzyme.HybridArrayLength'] = 'vtableLength'
        class_struct.append(vtable_type, 'vtable')

        return [('java.lang.Class', class_struct)]

    @staticmethod
    def for_view(view: BinaryView):
        return new_class(
            name='SubstrateClass',
            bases=(SubstrateClass,),
            kwds={
                'metaclass': SubstrateClassMeta,
                'view': view,
            },
            exec_body=None,
        )

class SubstrateClassMeta(SubstrateType):
    raw_name = 'java.lang.Class'
    array_length_member = 'vtableLength'
    array_base_member = 'vtable'

    heap: SvmHeap

    def __init__(cls, name, bases, namespace, *args, **kwargs):
        super().__init__(name, bases, namespace, *args, **kwargs)
        cls.heap = SvmHeap.for_view(cls.view)

    def is_instance(cls, hub_addr: int, name: str | None = None, **kwargs):
        metaclass_hub_addr = cls.heap.read_pointer(hub_addr)
        expected_metaclass_hub_addr = cls.hub_address

        if expected_metaclass_hub_addr is None:
            if name == 'java.lang.Class':
                if metaclass_hub_addr != hub_addr:
                    return False
            elif not cls.is_instance(metaclass_hub_addr, 'java.lang.Class'):
                return False

            if not (metaclass_var := cls.heap.view.get_data_var_at(metaclass_hub_addr)) or metaclass_var.type != cls.type:
                cls.hub_address = metaclass_hub_addr
        elif metaclass_hub_addr != expected_metaclass_hub_addr:
            return False
        
        from .string import is_string_instance
        hub_accessor = cls.heap.view.typed_data_accessor(hub_addr, cls.heap.view.get_type_by_name('java.lang.Class'))
        if (string := cls.heap.resolve_target(hub_accessor['name'].value)) is None or not is_string_instance(
            cls.heap,
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
            if name in ['java.lang.String', '[B'] and (stype := SubstrateType.by_name(cls.heap.view, name)).hub_address is None:
                stype.hub_address = hub_addr

        return True

    def find_by_name(cls, name: str):
        if (class_type := cls.heap.view.get_type_by_name("java.lang.Class")):
            search_offset = class_type ['name'].offset
        else:
            search_offset = 0x28

        from .string import find_strings_by_value
        for string in find_strings_by_value(cls.heap, name):
            for addr in cls.heap.find_refs_to(string):
                if cls.is_instance(hub := addr - search_offset, name):
                    SubstrateType.by_name(cls.view, name).hub_address = hub
                    return hub
