from binaryninja import BinaryView, Endianness
from binaryninja.types import StructureType

from .reference_map import decode_reference_map
class SvmHeap:
    _instances: dict[BinaryView, 'SvmHeap'] = {}
    view: BinaryView
    start: int
    end: int
    
    base: int | None
    compression_shift: int

    instance_reference_map_offset: int | None
    instance_reference_map_len: int | None
    _hub_to_reference_map_index: dict[int, int]
    class_hub: int

    def __init__(self, view: BinaryView, start: int, end: int, base: int | None, compression_shift: int, class_hub: int):
        self.view = view
        self.start = start
        self.end = end
        self.base = base
        self.compression_shift = compression_shift

        self.instance_reference_map_offset = None
        self.instance_reference_map_len = None
        self._hub_to_reference_map_index = {}
        
        self.class_hub = class_hub

    @property
    def address_size(self) -> int:
        assert self.view.arch is not None
        return self.view.arch.address_size

    def resolve_target(self, addr: int):
        # TODO: analyse reserved_bit
        addr >>= 3
        addr <<= 3

        resolved = ((self.base or 0) + addr) << self.compression_shift
        if resolved < self.start:
            return None
        if resolved > self.end:
            return None

        return resolved

    def read_pointer(self, addr: int):
        try:
            if (ptr := self.view.read_pointer(addr)) is None:
                return None
        except ValueError:
            return None

        if ptr == 0:
            return None

        return self.resolve_target(ptr)

    def make_pointer(self, addr: int):
        return (addr - (self.base or 0)) >> self.compression_shift

    def relative_offsets_by_index(self, index: int):
        if self.instance_reference_map_offset is None:
            return
        
        reference_map = self.instance_reference_map_offset + index
        num_entries = self.view.read_int(reference_map, 4, True)
        for offset in decode_reference_map(
            self.view.read(reference_map, 4 + (num_entries * self.address_size)),
            reference_size=self.address_size
        ):
            yield offset

    def find_refs_to(self, target: int):
        assert self.view.arch is not None

        target_ptr = self.make_pointer(target).to_bytes(
            self.address_size,
            "little" if self.view.arch.endianness == Endianness.LittleEndian else "big",
        )

        pattern = f"[\\x{target_ptr[0]:02x}-\\x{target_ptr[0]+7:02x}]" + "".join(f"\\x{b:02x}"for b in target_ptr[1:])

        for (addr, _) in self.view.search(
            pattern,
            self.start,
            self.end,
            align=8,
        ):
            yield addr

    def find_refs_from(self, source: int):
        if self.instance_reference_map_offset is None:
            return
        
        if (hub := self.read_pointer(source)) is None:
            return

        if hub in self._hub_to_reference_map_index:
            index = self._hub_to_reference_map_index[hub]
        else:
            class_type = self.view.get_type_by_name('java.lang.Class')
            assert class_type is not None
            index = self._hub_to_reference_map_index[hub] = self.view.typed_data_accessor(
                hub,
                class_type,
            )['referenceMapIndex'].value

        for offset in self.relative_offsets_by_index(index):
            if (target := self.read_pointer(source + offset)) is not None:
                yield target

    def save_to_metadata(self):
        self.view.store_metadata('LyticEnzyme.heap', {
            'start': self.start,
            'end': self.end,
            'base': self.base or 0,
            'compression_shift': self.compression_shift or 0,
            'class_hub': self.class_hub,
        })

    @classmethod
    def from_metadata(cls, view: BinaryView):
        try:
            if not isinstance(metadata := view.query_metadata('LyticEnzyme.heap'), dict):
                return None
            if not isinstance(start := metadata['start'], int):
                return None
            if not isinstance(end := metadata['end'], int):
                return None
            if not isinstance(base := metadata['base'], int):
                return None
            if not isinstance(compression_shift := metadata['compression_shift'], int):
                return None
            if not isinstance(class_hub := metadata['class_hub'], int):
                return None
            
            return cls(view, start, end, base, compression_shift, class_hub)
        except KeyError:
            return None

    # TODO: alignment masks
    @classmethod
    def for_view(cls, view: BinaryView, allow_metadata = True) -> 'SvmHeap':
        assert view.arch is not None

        if view in cls._instances:
            return cls._instances[view]

        if allow_metadata and (heap := cls.from_metadata(view)):
            return heap
        
        if (heap_section := view.get_section_by_name(".svm_heap")) is None:
            raise ValueError('Unable to find section .svm_heap in view')

        search_string = b"java.lang.Class"
        search_string = len(search_string).to_bytes(4, "little" if view.arch.endianness == Endianness.LittleEndian else "big") + search_string
        
        byte_array_type = view.get_type_by_name("byte[]")
        if isinstance(byte_array_type, StructureType):
            search_offset = byte_array_type['len'].offset
        else:
            search_offset = 0xc

        potential_byte_arrays = [
            addr - search_offset
            for (addr, _) in view.find_all_data(
                heap_section.start,
                heap_section.end,
                search_string,
            )
        ]

        potential_heap_base = heap_section.start - view.read_int(heap_section.start, view.arch.address_size)

        for addr in potential_byte_arrays:
            byte_array_hub_addr = view.read_pointer(addr)
            for use_heap_base in [False, True]:
                for compression_shift in range(4 if use_heap_base else 1):
                    byte_array_hub_addr <<= compression_shift
                    if use_heap_base:
                        byte_array_hub_addr += potential_heap_base

                    try:
                        metaclass_hub_addr = view.read_pointer(byte_array_hub_addr)
                        resolved_metaclass_hub_addr = metaclass_hub_addr << compression_shift
                        if use_heap_base:
                            resolved_metaclass_hub_addr += potential_heap_base

                        hub_of_metaclass = view.read_pointer(resolved_metaclass_hub_addr)
                        if metaclass_hub_addr == hub_of_metaclass:
                            heap = SvmHeap(
                                view,
                                heap_section.start,
                                heap_section.end,
                                potential_heap_base if use_heap_base else None,
                                compression_shift,
                                resolved_metaclass_hub_addr,
                            )
                            if allow_metadata:
                                heap.save_to_metadata()
                            
                            cls._instances[view] = heap
                            return heap
                    except ValueError:
                        pass
        
        raise ValueError
