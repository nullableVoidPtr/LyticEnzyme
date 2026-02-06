from binaryninja import BinaryView, Endianness
from binaryninja.types import Type, TypeBuilder
from binaryninja.enums import NamedTypeReferenceClass

from types import new_class

from ...heap import SvmHeap
from ..meta import SubstrateType
from ..svm import create_hub_builder

class SubstrateByteArray:
    # Can be derived, though we need it
    # for checks before we have confirmed the hub for java.lang.Class
    @staticmethod
    def make_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
        byte_array_struct = create_hub_builder(view)
        byte_array_struct.add_member_at_offset('len', TypeBuilder.int(4, True), 0xc)
        byte_array_struct.append(
            TypeBuilder.array(
                TypeBuilder.named_type_reference(
                    NamedTypeReferenceClass.TypedefNamedTypeClass,
                    'jbyte',
                    width=1,
                ),
                1,
            ),
            'data',
        )

        return [('byte[]', byte_array_struct)]

    @classmethod
    def is_instance(cls, addr: int, value: bytes | None = None, **kwargs):
        if (expected_byte_array_hub_addr := kwargs.get('expected_byte_array_hub_addr')) is not None:
            if cls.heap.read_pointer(addr) != expected_byte_array_hub_addr:
                return False
        elif not cls._is_instance(addr, **kwargs):
            return False

        length = cls.view.read_int(addr + cls['len'].offset, 4)
        
        if value is not None:
            if length != len(value):
                return False

            return cls.view.read(addr + cls['data'].offset, len(value)) == value

        return cls.heap.start <= addr + cls['data'].offset + length <= cls.heap.end

    @classmethod
    def find_by_value(cls, value: bytes):
        search_string = len(value).to_bytes(4, "little" if cls.view.arch.endianness == Endianness.LittleEndian else "big") + value
        search_offset = cls['len'].offset

        for (addr, _) in cls.view.find_all_data(
            cls.heap.start,
            cls.heap.end,
            search_string,
        ):
            if cls.is_instance(byte_array := addr - search_offset):
                yield byte_array

    @staticmethod
    def for_view(view: BinaryView | SvmHeap):
        return new_class(
            name='SubstrateByteArray',
            kwds={
                'metaclass': SubstrateByteArrayMeta,
                'view': view,
            },
            exec_body=None,
        )

class SubstrateByteArrayMeta(SubstrateType, base_specialisation=SubstrateByteArray):
    raw_name = '[B'
    name = 'byte[]'
