from binaryninja import BinaryView, TypedDataAccessor
from binaryninja.types import TypeBuilder, StructureType

from types import new_class
from typing import Callable

from ...heap import SvmHeap
from ..meta import SubstrateType
from ..builder import ObjectBuilder

def java_hash_code(value: str):
    res = 0
    for c in value:
        res = (res * 31 + ord(c)) & (2**32 - 1)
    if res & 2**31:
        res -= 2**32
    return res

def accessor_as_int(accessor: TypedDataAccessor | list[TypedDataAccessor]) -> int:
    assert not isinstance(accessor, list)
    return int(accessor)

class SubstrateString:
    heap: SvmHeap # TODO: remove when ABC is defined
    view: BinaryView
    typed_data_accessor: Callable[[int], TypedDataAccessor]

    @staticmethod
    def make_type_definitions(view: BinaryView):
        return [
            ObjectBuilder(view, 'java.lang.String', members=[
                ('byte[]', 'value'),
                (TypeBuilder.int(4, True), 'hash'),
                (TypeBuilder.char(), 'coder'),
                (TypeBuilder.bool(), 'hashIsZero'),
            ]),
        ]

    @classmethod
    def is_instance(cls, addr: int, value: str | None = None, **kwargs):
        if (expected_string_hub_addr := kwargs.get('expected_string_hub_addr')) is not None:
            if cls.heap.read_pointer(addr) != expected_string_hub_addr:
                return False
        elif not cls._is_instance(addr, **kwargs):
            return False

        accessor = cls.typed_data_accessor(addr)
        if value is not None and java_hash_code(value) != accessor_as_int(accessor['hash']):
            return False

        if (byte_array := cls.heap.resolve_target(accessor_as_int(accessor['value']))) is None:
            return False

        from .bytearray import SubstrateByteArray
        return SubstrateByteArray.for_view(cls.view).is_instance(
            byte_array,
            value.encode('utf-8' if accessor_as_int(accessor['coder']) == 0 else 'utf-16') if value is not None else None,
            **kwargs,
        )

    # TODO: check if UTF16 logic works

    @classmethod
    def read_unchecked(cls, addr: int):
        accessor = cls.typed_data_accessor(addr)
        if (byte_array := cls.heap.resolve_target(accessor_as_int(accessor['value']))) is None:
            return None

        array_type = cls.view.get_type_by_name('byte[]')
        assert isinstance(array_type, StructureType)

        return cls.view.read(
            byte_array + array_type['data'].offset,
            cls.view.read_int(byte_array + array_type['len'].offset, 4),
        ).decode()

    @classmethod
    def read(cls, addr: int):
        if not cls.is_instance(addr):
            return None

        accessor = cls.typed_data_accessor(addr)
        if (byte_array := cls.heap.resolve_target(accessor_as_int(accessor['value']))) is None:
            return None

        from .bytearray import SubstrateByteArray
        array_type = SubstrateByteArray.for_view(cls.view)
        if not array_type.is_instance(byte_array):
            return None

        try:
            value = cls.view.read(
                byte_array + array_type['data'].offset,
                cls.view.read_int(byte_array + array_type['len'].offset, 4),
            ).decode('utf-8' if accessor_as_int(accessor['coder']) == 0 else 'utf-16')
        except ValueError:
            return None
        
        if java_hash_code(value) != accessor_as_int(accessor['hash']):
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
