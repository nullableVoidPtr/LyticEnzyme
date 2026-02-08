from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder

from types import new_class

from ...heap import SvmHeap
from ..meta import SubstrateType
from ..svm import create_hub_builder
from .object import make_object_ptr

def java_hash_code(value: str):
    res = 0
    for c in value:
        res = (res * 31 + ord(c)) & (2**32 - 1)
    if res & 2**31:
        res -= 2**32
    return res

class SubstrateString:
    @staticmethod
    def make_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
        string_struct = create_hub_builder(view)
        string_struct.append(make_object_ptr(view, 'byte[]'), 'value')
        string_struct.append(TypeBuilder.int(4, True), 'hash')
        string_struct.append(TypeBuilder.char(), 'coder')
        string_struct.append(TypeBuilder.bool(), 'hashIsZero')

        return [('java.lang.String', string_struct)]

    @classmethod
    def is_instance(cls, addr: int, value: str | None = None, **kwargs):
        if (expected_string_hub_addr := kwargs.get('expected_string_hub_addr')) is not None:
            if cls.heap.read_pointer(addr) != expected_string_hub_addr:
                return False
        elif not cls._is_instance(addr, **kwargs):
            return False

        accessor = cls.typed_data_accessor(addr)
        if value is not None and java_hash_code(value) != accessor['hash'].value:
            return False

        if (byte_array := cls.heap.resolve_target(accessor['value'].value)) is None:
            return False

        from .bytearray import SubstrateByteArray
        return SubstrateByteArray.for_view(cls.view).is_instance(
            byte_array,
            value.encode('utf-8' if accessor['coder'].value == 0 else 'utf-16') if value is not None else None,
            **kwargs,
        )

    # TODO: check if UTF16 logic works

    @classmethod
    def read_unchecked(cls, addr: int):
        accessor = cls.typed_data_accessor(addr)
        if (byte_array := cls.heap.resolve_target(accessor['value'].value)) is None:
            return None

        array_type = cls.heap.view.get_type_by_name('byte[]')
        return cls.heap.view.read(
            byte_array + array_type['data'].offset,
            cls.heap.view.read_int(byte_array + array_type['len'].offset, 4),
        ).decode()

    @classmethod
    def read(cls, addr: int):
        if not cls.is_instance(addr):
            return None

        accessor = cls.typed_data_accessor(addr)
        if (byte_array := cls.heap.resolve_target(accessor['value'].value)) is None:
            return None

        from .bytearray import SubstrateByteArray
        array_type = SubstrateByteArray.for_view(cls.view)
        if not array_type.is_instance(byte_array):
            return None

        try:
            value = cls.view.read(
                byte_array + array_type['data'].offset,
                cls.view.read_int(byte_array + array_type['len'].offset, 4),
            ).decode('utf-8' if accessor['coder'].value == 0 else 'utf-16')
        except ValueError:
            return None
        
        if java_hash_code(value) != accessor['hash'].value:
            return None

        return value

    @classmethod
    def find_by_value(cls, value: str):
        search_offset = cls['value'].offset

        from .bytearray import SubstrateByteArray
        array_type = SubstrateByteArray.for_view(cls.heap)
        for byte_array in array_type.find_by_value(value.encode()):
            for addr in cls.heap.find_refs_to(byte_array):
                if cls.is_instance(string := addr - search_offset, value):
                    yield string

    @staticmethod
    def for_view(view: BinaryView | SvmHeap):
        return new_class(
            name='SubstrateString',
            kwds={
                'metaclass': SubstrateStringMeta,
                'view': view,
            },
            exec_body=None,
        )

class SubstrateStringMeta(SubstrateType, base_specialisation=SubstrateString):
    raw_name = 'java.lang.String'
