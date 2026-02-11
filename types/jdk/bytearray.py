from binaryninja import BinaryView, Endianness
from binaryninja.types import Type, TypeBuilder, StructureMember

from types import new_class

from ...heap import SvmHeap
from ..meta import SubstrateType
from ..builder import ObjectBuilder

class SubstrateByteArray:
    heap: SvmHeap # TODO: remove when ABC is defined
    view: BinaryView

    # Can be derived, though we need it
    # for checks before we have confirmed the hub for java.lang.Class
    @staticmethod
    def make_type_definitions(view: BinaryView):
        return [ObjectBuilder(view, 'byte[]', members=[
            StructureMember(Type.int(4, True), 'len', offset=0xc),
            (TypeBuilder.array(ObjectBuilder.named_typedef('jbyte', width=1), 1), 'data'),
        ])]

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
        assert cls.view.arch is not None

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
