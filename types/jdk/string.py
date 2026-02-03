from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder

from ...heap import SvmHeap
from ..svm import create_hub_builder
from .object import make_object_ptr

def string_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
    string_struct = create_hub_builder(view)
    string_struct.append(make_object_ptr(view, 'byte[]'), 'value')
    string_struct.append(TypeBuilder.int(4, True), 'hash')
    string_struct.append(TypeBuilder.char(), 'coder')
    string_struct.append(TypeBuilder.bool(), 'hashIsZero')

    return [('java.lang.String', string_struct)]

def java_hash_code(value: str):
    res = 0
    for c in value:
        res = (res * 31 + ord(c)) & (2**32 - 1)
    if res & 2**31:
        res -= 2**32
    return res

def is_string_instance(heap: SvmHeap, addr: int, value: str | None = None, **kwargs):
    from .. import is_instance_of_type
    if (expected_string_hub_addr := kwargs.get('expected_string_hub_addr')) is not None:
        if heap.read_pointer(addr) != expected_string_hub_addr:
            return False
    elif not is_instance_of_type(heap, addr, 'java.lang.String', **kwargs):
        return False

    accessor = heap.view.typed_data_accessor(addr, heap.view.get_type_by_name('java.lang.String'))
    if value is not None:
        if java_hash_code(value) != accessor['hash'].value:
            return False

    if (byte_array := heap.resolve_target(accessor['value'].value)) is None:
        return False

    from .bytearray import is_byte_array

    return is_byte_array(
        heap,
        byte_array,
        value.encode('utf-8' if accessor['coder'].value == 0 else 'utf-16') if value is not None else None,
        **kwargs,
    )

# TODO: UTF16 logic

def read_string_unchecked(heap: SvmHeap, addr: int):
    accessor = heap.view.typed_data_accessor(addr, heap.view.get_type_by_name('java.lang.String'))
    if (byte_array := heap.resolve_target(accessor['value'].value)) is None:
        return None

    array_type = heap.view.get_type_by_name('byte[]')
    return heap.view.read(
        byte_array + array_type['data'].offset,
        heap.view.read_int(byte_array + array_type['len'].offset, 4),
    ).decode()

def read_string(heap: SvmHeap, addr: int):
    view = heap.view

    from .. import is_instance_of_type
    if not is_instance_of_type(heap, addr, 'java.lang.String'):
        return None

    accessor = view.typed_data_accessor(addr, view.get_type_by_name('java.lang.String'))
    if (byte_array := heap.resolve_target(accessor['value'].value)) is None:
        return None
    if not is_instance_of_type(heap, byte_array, '[B'):
        return None

    array_type = view.get_type_by_name('byte[]')
    try:
        value = view.read(
            byte_array + array_type['data'].offset,
            view.read_int(byte_array + array_type['len'].offset, 4),
        ).decode('utf-8' if accessor['coder'].value == 0 else 'utf-16')
    except ValueError:
        return None
    
    if java_hash_code(value) != accessor['hash'].value:
        return None

    return value

def find_strings_by_value(heap: SvmHeap, value: str):
    if (string_type := heap.view.get_type_by_name("java.lang.String")):
        search_offset = string_type['value'].offset
    else:
        search_offset = 0x8

    from .bytearray import find_byte_array_by_value
    for byte_array in find_byte_array_by_value(heap, value.encode()):
        for addr in heap.find_refs_to(byte_array):
            if is_string_instance(heap, string := addr - search_offset, value):
                yield string
