from binaryninja import BinaryView, Endianness
from binaryninja.types import Type, TypeBuilder
from binaryninja.enums import NamedTypeReferenceClass

from ...heap import SvmHeap
from ..svm import create_hub_builder

def byte_array_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
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
    byte_array_struct.attributes["LyticEnzyme.VariableLength"] = ""

    return [('byte[]', byte_array_struct)]

def is_byte_array(heap: SvmHeap, addr: int, value: bytes | None = None, **kwargs):
    from .. import is_instance_of_type
    if (expected_byte_array_hub_addr := kwargs.get('expected_byte_array_hub_addr')) is not None:
        if heap.read_pointer(addr) != expected_byte_array_hub_addr:
            return False
    elif not is_instance_of_type(heap, addr, '[B', **kwargs):
        return False

    array_type = heap.view.get_type_by_name('byte[]')
    length = heap.view.read_int(addr + array_type['len'].offset, 4)
    
    if value is not None:
        if length != len(value):
            return False

        return heap.view.read(addr + array_type['data'].offset, len(value)) == value
    
    return heap.start <= addr + array_type['data'].offset + length <= heap.end

def find_byte_array_by_value(heap: SvmHeap, value: bytes):
    search_string = len(value).to_bytes(4, "little" if heap.view.arch.endianness == Endianness.LittleEndian else "big") + value

    if (byte_array_type := heap.view.get_type_by_name("byte[]")):
        search_offset = byte_array_type['len'].offset
    else:
        search_offset = 0xc

    from .. import is_instance_of_type
    for (addr, _) in heap.view.find_all_data(
        heap.start,
        heap.end,
        search_string,
    ):
        if is_instance_of_type(heap, byte_array := addr - search_offset, '[B'):
            yield byte_array

