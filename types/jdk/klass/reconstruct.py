from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder, IntegerType, StructureMember

from typing import Sequence
from collections import Counter
from itertools import islice

from ....heap import SvmHeap
from ...builder import LyticTypeBuilder, ObjectBuilder
from ...layout_encoding import LayoutEncoding, ArrayTag

class TypeReconstructor(ObjectBuilder):
    covered_offsets: set[int]
    outref_offsets: set[int] | None

    def __init__(self, view: BinaryView, name: str, members: Sequence[tuple[LyticTypeBuilder | Type | TypeBuilder, str] | StructureMember] | None, **kwargs):
        super().__init__(view, name, members, **kwargs)

        self.covered_offsets = set()
        self.outref_offsets = None

    def accessor(self, heap: SvmHeap, address: int):
        return ReconstructorAccessor(heap, address, self)

    def is_covered(self, offset: int, width: int):
        return any(i in self.covered_offsets for i in range(offset, offset + width))

    def aligned_offsets(self, width: int, *, start: int = 0, end: int | None = None):
        for offset in range(start, end or self.width, width):
            if self.is_covered(offset, width):
                continue

            yield offset

    def add_member_at_offset(self, name: str | None, _type: LyticTypeBuilder | Type | TypeBuilder | str, offset: int, **kwargs):
        super().add_member_at_offset(
            name,
            _type,
            offset,
            **kwargs
        )

        member = self[name]
        assert member is not None
        self.covered_offsets.update(range(offset, offset + member.type.width))
        

class ReconstructorAccessor:
    heap: SvmHeap
    address: int
    type: TypeReconstructor

    def __init__(self, heap: SvmHeap, address: int, _type: TypeReconstructor):
        self.heap = heap
        self.address = address
        self.type = _type

    def __getitem__(self, name: str):
        if (member := self.type[name]) is None:
            return None

        sign = False
        if isinstance(member.type, IntegerType):
            sign = bool(member.type.signed)

        res = self.heap.view.read_int(self.address + member.offset, member.type.width, sign=sign)

        if self.type.outref_offsets is None or member.offset not in self.type.outref_offsets:
            return res
        
        return self.heap.resolve_target(res)
            

    def aligned_ints(self, width: int, *, start: int = 0, end: int | None = None, sign: bool = False):
        for offset in self.type.aligned_offsets(width, start=start, end=end):
            yield offset, self.heap.view.read_int(
                self.address + offset,
                width,
                sign=sign,
            )

    def aligned_refs(self, *, start: int = 0, end: int | None = None):
        for offset in self.type.aligned_offsets(self.heap.address_size, start=start, end=end):
            if (target := self.heap.read_pointer(self.address + offset)) is None:
                continue

            yield offset, target

    def read_pointer(self, offset: int):
        return self.heap.read_pointer(self.address + offset)

def reconstruct_hub_type(heap: SvmHeap, class_hub_addr: int):
    if heap.instance_reference_map_offset is None:
        raise ValueError()
    
    class_type_builder = TypeReconstructor(heap.view, 'java.lang.Class', members=[
        (TypeBuilder.int(4, True), 'identityHashCode'),
        (TypeBuilder.int(4, True), 'vtableLength'),
    ])

    class_hub = class_type_builder.accessor(heap, class_hub_addr)

    potential_lengths = Counter()
    last = None
    for ref in heap.find_refs_to(class_hub_addr):
        if last is None:
            last = ref
            continue

        gap = ref - last
        potential_lengths[gap] += 1

        last = ref
    
    potential_length = potential_lengths.most_common(1)[0][0]

    potential_ref_map_offsets = []
    array_base_offset = None
    layout_encoding_defined = False
    for offset, raw in class_hub.aligned_ints(4, end=potential_length, sign=True):
        if raw >= 0:
            if raw < heap.instance_reference_map_len:
                potential_ref_map_offsets.append(offset)
            continue

        try:
            layout_encoding = LayoutEncoding.parse(raw)
        except ValueError:
            continue

        if layout_encoding.array_tag != ArrayTag.HYBRID_PRIMITIVE:
            continue
        
        assert layout_encoding.array_base_offset is not None
        if layout_encoding.array_base_offset > potential_length:
            continue

        if not layout_encoding_defined:
            class_type_builder.add_member_at_offset(
                'layoutEncoding',
                TypeBuilder.int(4, True),
                offset,
            )
            array_base_offset = class_type_builder.width = layout_encoding.array_base_offset
            layout_encoding_defined = True

    if not layout_encoding_defined:
        raise ValueError('Could not identify layoutEncoding')

    assert isinstance(array_base_offset, int)

    potential_component_type_offsets = set()

    from ..string import SubstrateString
    string_type = SubstrateString.for_view(heap)
    potential_companion_offsets = set()
    name_defined = False
    for offset, target_ptr in class_hub.aligned_ints(8):
        if target_ptr == 0:
            potential_component_type_offsets.add(offset)
            continue

        if (target := heap.resolve_target(target_ptr)) is None:
            continue

        if (target_hub := heap.read_pointer(target)) is None:
            continue

        if heap.read_pointer(target_hub) != class_hub_addr:
            continue

        potential_companion_offsets.add(offset)
        if not name_defined and (name_of_string := heap.read_pointer(target_hub + offset)) is not None:
            name = target
            string_hub = target_hub
            if heap.read_pointer(name_of_string) != string_hub:
                continue

            try:
                if string_type.read_unchecked(name) != 'java.lang.Class':
                    continue
                if string_type.read_unchecked(name_of_string) != 'java.lang.String':
                    continue
            except:
                continue

            class_type_builder.add_member_at_offset(
                'name',
                'java.lang.String',
                offset,
            )
            potential_companion_offsets.remove(offset)
            name_defined = True

    if not name_defined:
        raise ValueError('Could not identify name')

    name_member = class_type_builder['name']
    assert name_member is not None
    name_offset = name_member.offset

    name_addr = class_hub['name']
    assert name_addr is not None
    string_object = heap.resolve_target(name_addr)
    assert string_object is not None
    string_hub = heap.read_pointer(string_object)
    assert string_hub is not None

    for offset in potential_companion_offsets:
        if class_type_builder.is_covered(offset, heap.address_size):
            continue

        if (companion := heap.read_pointer(class_hub_addr + offset)) is None:
            continue

        if (companion_hub := heap.read_pointer(companion)) is None:
            continue

        if (name := heap.read_pointer(companion_hub + name_offset)) is None:
            continue

        try:
            if string_type.read_unchecked(name) != 'com.oracle.svm.core.hub.DynamicHubCompanion':
                continue
        except:
            continue

        class_type_builder.add_member_at_offset(
            'companion',
            'com.oracle.svm.core.hub.DynamicHubCompanion',
            offset,
        )
        break
    else:
        raise ValueError('Could not identify companion')

    companion_member = class_type_builder['companion']
    assert companion_member is not None
    companion_offset = companion_member.offset
    for offset in potential_ref_map_offsets:
        if class_type_builder.is_covered(offset, 4):
            continue

        try:
            ref_gen = heap.relative_offsets_by_index(
                heap.view.read_int(string_hub + offset, 4, True),
            )
            if len(string_refs := list(islice(ref_gen, 2))) != 1:
                continue

            if string_refs[0] != heap.address_size:
                continue

            ref_gen = heap.relative_offsets_by_index(
                heap.view.read_int(class_hub_addr + offset, 4, True),
            )

            if len(class_hub_refs := list(islice(ref_gen, 5))) == 5:
                continue
            if name_offset not in class_hub_refs:
                continue
            if companion_offset not in class_hub_refs:
                continue
        except ValueError:
            continue

        class_type_builder.add_member_at_offset(
            'referenceMapIndex',
            TypeBuilder.int(4, True),
            offset,
        )
        break
    else:
        raise ValueError('Could not identify referenceMapIndex')
    
    ref_map_index = class_hub['referenceMapIndex']
    assert ref_map_index is not None
    class_type_builder.outref_offsets = set(
        heap.relative_offsets_by_index(ref_map_index)
    )

    companion_addr = class_hub['companion']
    assert companion_addr is not None
    companion_hub = heap.read_pointer(companion_addr)
    assert companion_hub is not None

    is_closed = False
    for offset in class_type_builder.outref_offsets:
        if class_type_builder.is_covered(offset, heap.address_size):
            continue

        if (slots := heap.read_pointer(class_hub_addr + offset)) is None:
            continue
        if (int_array_hub := heap.read_pointer(slots)) is None:
            continue
        if (name_of_array := heap.read_pointer(int_array_hub + name_offset)) is None:
            continue

        try:
            if string_type.read_unchecked(name_of_array) != '[I':
                continue
        except:
            continue

        class_type_builder.add_member_at_offset(
            'openTypeWorldTypeCheckSlots',
            'int[]',
            offset,
        )

        break
    else:
        vtable_length_member = class_type_builder['vtableLength']
        assert vtable_length_member is not None
        slot_start = (
            vtable_length_member.offset
            + vtable_length_member.type.width
        )
        slot_end = min(
            m.offset
            for m in class_type_builder.members
            if m.name not in ['vtableLength', 'identityHashCode']
        )

        known_hubs = [
            class_hub,
            class_type_builder.accessor(heap, companion_hub),
            class_type_builder.accessor(heap, string_hub),
        ]

        start_offsets = Counter()
        for hub in known_hubs:
            for type_id_offset, type_id in hub.aligned_ints(2, start=slot_start, end=slot_end, sign=True):
                if type_id == 0:
                    continue

                for start_offset, start_value in hub.aligned_ints(2, start=type_id_offset + 2, sign=True):
                    if start_value != type_id:
                        continue

                    start_offsets[start_offset] += 1

        class_type_builder.add_member_at_offset(
            'typeCheckStart',
            TypeBuilder.int(2, True),
            start_offset := start_offsets.most_common(1)[0][0],
        )
        is_closed = True

    potential_component_type_offsets = list(
        set(
            offset
            for offset in potential_component_type_offsets
            if not class_type_builder.is_covered(offset, heap.address_size)
        )
        & class_type_builder.outref_offsets
    )

    if len(potential_component_type_offsets) == 1:
        class_type_builder.add_member_at_offset(
            'componentType',
            'java.lang.Class',
            potential_component_type_offsets[0]
        )
    elif (name_value := heap.read_pointer(class_hub['name'] + string_type.type['value'].offset)) is not None:
        if (byte_array_hub_addr := heap.read_pointer(name_value)) is not None:
            if string_type.read_unchecked(
                (byte_array_hub := class_type_builder.accessor(heap, byte_array_hub_addr))['name']
            ) == '[B':
                for offset, byte_hub_addr in byte_array_hub.aligned_refs():
                    if (byte_name := heap.read_pointer(byte_hub_addr + name_offset)) is None:
                        continue

                    try:
                        if string_type.read_unchecked(byte_name) != 'byte':
                            continue
                    except:
                        continue

                    class_type_builder.add_member_at_offset(
                        'componentType',
                        'java.lang.Class',
                        offset,
                    )
                    break

    for offset, flags in class_hub.aligned_ints(2, sign=True):
        if flags != 0x420:
            continue

        class_type_builder.add_member_at_offset(
            'flags',
            Type.named_type_from_registered_type(heap.view, 'DynamicHubFlags'),
            offset,
        )

        hub_type_offset = offset + 2
        if not class_type_builder.is_covered(hub_type_offset, 1) and hub_type_offset < class_type_builder.width:
            class_type_builder.add_member_at_offset(
                'hubType',
                TypeBuilder.int(1, True),
                hub_type_offset,
                overwrite_existing=False,
            )

            layer_id_offset = hub_type_offset + 1
            if not class_type_builder.is_covered(layer_id_offset, 1) and layer_id_offset < class_type_builder.width:
                class_type_builder.add_member_at_offset(
                    'layerId',
                    TypeBuilder.int(1, True),
                    layer_id_offset,
                    overwrite_existing=False,
                )

        break

    for offset, id_hash_offset in class_hub.aligned_ints(2, sign=True):
        if id_hash_offset != 0x8:
            continue

        class_type_builder.add_member_at_offset(
            'identityHashOffset',
            TypeBuilder.int(2, True),
            offset,
        )
        break
    else:
        raise ValueError('Could not identify identityHashOffset')

    companion_size = heap.view.read_int(companion_hub + class_type_builder['layoutEncoding'].offset, 4)
    for offset, monitor_offset in class_type_builder.accessor(heap, companion_hub).aligned_ints(2, sign=True):
        if monitor_offset == 0:
            continue
        if monitor_offset > companion_size - heap.address_size:
            continue
        if monitor_offset % heap.address_size != 0:
            continue

        class_type_builder.add_member_at_offset(
            'monitorOffset',
            TypeBuilder.int(2, True),
            offset,
        )
        break

    def search_classes():
        for addr in heap.find_refs_to(class_hub_addr):
            hub = class_type_builder.accessor(heap, addr)
            if (other_companion := hub['companion']) is None:
                continue
            if heap.read_pointer(other_companion) != companion_hub:
                continue

            yield hub

    if is_closed:
        vtable_length_member = class_type_builder['vtableLength']
        assert vtable_length_member is not None
        slot_start = (
            vtable_length_member.offset
            + vtable_length_member.type.width
        )
        slot_end = min(
            m.offset
            for m in class_type_builder.members
            if m.name not in ['vtableLength', 'identityHashCode']
        )

        potential_slot_index_offsets = Counter()
        potential_check_range_offsets = Counter()
        non_zero_slots = [False for _ in range((slot_end - slot_start) // 2)]
        for hub in search_classes():
            start = hub['typeCheckStart']
            for index, (offset, value) in enumerate(
                hub.aligned_ints(2, start=slot_start, sign=True)
            ):
                if offset < slot_end:
                    if value != 0:
                        non_zero_slots[index] = True

                    if index > 0 and value == start:
                        for slot_index_offset, value in hub.aligned_ints(2, start=offset + 2, sign=True):
                            if value != index:
                                continue

                            potential_slot_index_offsets[slot_index_offset] += 1
                
                # Leaf/terminal classes should be most common
                if value == 1:
                    potential_check_range_offsets[offset] += 1

        slot_index_offset = potential_slot_index_offsets.most_common(1)[0][0]
        class_type_builder.add_member_at_offset(
            'typeCheckSlot',
            TypeBuilder.int(2, True),
            slot_index_offset,
        )

        for check_range_offset, _ in potential_check_range_offsets.most_common():
            if check_range_offset == slot_index_offset:
                continue

            class_type_builder.add_member_at_offset(
                'typeCheckRange',
                TypeBuilder.int(2, True),
                check_range_offset,
            )
            break

        slot_length = next(i for i, v in enumerate(non_zero_slots + [False]) if v == False)
        while slot_length > 1:
            if not class_type_builder.is_covered(slot_start, slot_length * 2):
                break

            slot_length -= 1
                
        class_type_builder.add_member_at_offset(
            'closedTypeWorldTypeCheckSlots',
            TypeBuilder.array(
                Type.int(2, True),
                slot_length,
            ),
            slot_start,
        )
    else:
        slot_array = class_hub['openTypeWorldTypeCheckSlots']
        assert slot_array is not None
        array_base = slot_array + heap.address_size + 4 + 4
        known_hubs = [
            class_hub,
            class_type_builder.accessor(heap, companion_hub),
            class_type_builder.accessor(heap, string_hub),
        ]

        type_id_offsets = Counter()
        for hub in known_hubs:
            for offset, type_id in hub.aligned_ints(4):
                if type_id == 0:
                    continue

                for depth_offset, depth in class_hub.aligned_ints(2, sign=True):
                    if offset <= depth_offset < (offset + 4):
                        continue
                    if heap.view.read_int(array_base + (depth * 4), 4) != type_id:
                        continue

                    type_id_offsets[offset, depth_offset] += 1

        id_offset, depth_offset = type_id_offsets.most_common(1)[0][0]
        class_type_builder.add_member_at_offset(
            'typeID',
            TypeBuilder.int(4, True),
            id_offset,
        )
        class_type_builder.add_member_at_offset(
            'typeIDDepth',
            TypeBuilder.int(2, True),
            depth_offset,
        )


        for num_class_offset, num_class in class_hub.aligned_ints(2, sign=True):
            if num_class <= 0:
                continue

            for num_if_offset, num_if in class_hub.aligned_ints(2, sign=True):
                if num_class_offset == num_if_offset:
                    continue

                if num_if <= 0:
                    continue
                if num_class > num_if:
                    continue

                class_type_builder.add_member_at_offset(
                    'numClassTypes',
                    TypeBuilder.int(2, True),
                    num_class_offset,
                )
                class_type_builder.add_member_at_offset(
                    'numInterfaceTypes',
                    TypeBuilder.int(2, True),
                    num_if_offset,
                )
                break

    class_type_builder.add_member_at_offset(
        'vtable',
        TypeBuilder.array(
            LyticTypeBuilder.named_typedef(
                'org.graalvm.nativeimage.c.function.CFunctionPointer',
                alignment=heap.address_size,
                width=heap.address_size,
            ),
            1,
        ),
        array_base_offset,
    )

    return class_type_builder