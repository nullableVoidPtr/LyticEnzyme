from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder, IntegerType
from binaryninja.enums import NamedTypeReferenceClass

from types import new_class
from collections import Counter
from itertools import islice

from ...heap import SvmHeap
from ..meta import SubstrateType, ManagedHeapObject
from ..svm import create_hub_builder
from ..layout_encoding import LayoutEncoding, ArrayTag
from .object import make_object_ptr

class TypeReconstructor:
    builder: TypeBuilder
    covered_offsets: set[int]
    outref_offsets: set[int] | None

    def __init__(self, builder: TypeBuilder):
        self.builder = builder

        self.covered_offsets = set(range(self.builder.width))
        self.outref_offsets = None

    def __getitem__(self, name: str):
        return self.builder[name]

    @property
    def width(self):
        return self.builder.width

    @width.setter
    def width(self, width: int):
        self.builder.width = width

    @property
    def members(self):
        return self.builder.members

    def immutable_copy(self):
        return self.builder.immutable_copy()

    def accessor(self, heap: SvmHeap, address: int):
        return ReconstructorAccessor(heap, address, self)

    def is_covered(self, offset: int, width: int):
        return any(i in self.covered_offsets for i in range(offset, offset + width))

    def aligned_offsets(self, width: int, *, start: int = 0, end: int | None = None):
        for offset in range(start, end or self.width, width):
            if self.is_covered(offset, width):
                continue

            yield offset

    def add_member_at_offset(self, name: str, type: Type, offset: int, **kwargs):
        self.builder.add_member_at_offset(
            name,
            type,
            offset,
            **kwargs
        )
        self.covered_offsets.update(range(offset, offset + type.width))
        

class ReconstructorAccessor:
    heap: SvmHeap
    address: int
    type: TypeReconstructor

    def __init__(self, heap: SvmHeap, address: int, _type: TypeReconstructor):
        self.heap = heap
        self.address = address
        self.type = _type

    def __getitem__(self, name: str):
        member = self.type[name]

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


class SubstrateClass:
    @staticmethod
    def make_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
        class_struct = create_hub_builder(view)
        class_struct.add_member_at_offset('identityHashCode', TypeBuilder.int(4, True), 0x8)
        class_struct.add_member_at_offset('vtableLength', TypeBuilder.int(4, True), 0xc)
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

        return [('java.lang.Class', class_struct)]

    @classmethod
    def reconstruct_type(cls, class_hub_addr: int):
        if cls.heap.instance_reference_map_offset is None:
            raise ValueError()
        
        builder = create_hub_builder(cls.view)
        builder.append(
            TypeBuilder.int(4, True),
            'identityHashCode',
        )
        builder.append(
            TypeBuilder.int(4, True),
            'vtableLength',
        )

        class_type_builder = TypeReconstructor(builder)
        class_hub = class_type_builder.accessor(cls.heap, class_hub_addr)

        potential_lengths = Counter()
        last = None
        for ref in cls.heap.find_refs_to(class_hub_addr):
            if last is None:
                last = ref
                continue

            gap = ref - last
            potential_lengths[gap] += 1

            last = ref
        
        potential_length = potential_lengths.most_common(1)[0][0]

        potential_ref_map_offsets = []
        layout_encoding_defined = False
        for offset, raw in class_hub.aligned_ints(4, end=potential_length, sign=True):
            if raw >= 0:
                if raw < cls.heap.instance_reference_map_len:
                    potential_ref_map_offsets.append(offset)
                continue

            try:
                layout_encoding = LayoutEncoding.parse(raw)
            except ValueError:
                continue

            if layout_encoding.array_tag != ArrayTag.HYBRID_PRIMITIVE:
                continue
            
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

        potential_component_type_offsets = set()

        from .string import SubstrateString
        string_type = SubstrateString.for_view(cls.heap)
        potential_companion_offsets = set()
        name_defined = False
        for offset, target_ptr in class_hub.aligned_ints(8):
            if target_ptr == 0:
                potential_component_type_offsets.add(offset)
                continue

            if (target := cls.heap.resolve_target(target_ptr)) is None:
                continue

            if (target_hub := cls.heap.read_pointer(target)) is None:
                continue

            if cls.heap.read_pointer(target_hub) != class_hub_addr:
                continue

            potential_companion_offsets.add(offset)
            if not name_defined and (name_of_string := cls.heap.read_pointer(target_hub + offset)) is not None:
                name = target
                string_hub = target_hub
                if cls.heap.read_pointer(name_of_string) != string_hub:
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
                    make_object_ptr(cls.view, 'java.lang.String'),
                    offset,
                )
                potential_companion_offsets.remove(offset)
                name_defined = True

        if not name_defined:
            raise ValueError('Could not identify name')

        name_offset = class_type_builder['name'].offset
        for offset in potential_companion_offsets:
            if class_type_builder.is_covered(offset, cls.heap.address_size):
                continue

            if (companion := cls.heap.read_pointer(class_hub_addr + offset)) is None:
                continue

            if (companion_hub := cls.heap.read_pointer(companion)) is None:
                continue

            if (name := cls.heap.read_pointer(companion_hub + name_offset)) is None:
                continue

            try:
                if string_type.read_unchecked(name) != 'com.oracle.svm.core.hub.DynamicHubCompanion':
                    continue
            except:
                continue

            class_type_builder.add_member_at_offset(
                'companion',
                make_object_ptr(cls.view, 'com.oracle.svm.core.hub.DynamicHubCompanion'),
                offset,
            )
            break
        else:
            raise ValueError('Could not identify companion')

        companion_offset = class_type_builder['companion'].offset
        string_hub = cls.heap.read_pointer(cls.heap.read_pointer(
            class_hub_addr + class_type_builder['name'].offset
        ))
        for offset in potential_ref_map_offsets:
            if class_type_builder.is_covered(offset, 4):
                continue

            try:
                ref_gen = cls.heap.relative_offsets_by_index(
                    cls.view.read_int(string_hub + offset, 4, True),
                )
                if len(string_refs := list(islice(ref_gen, 2))) != 1:
                    continue

                if string_refs[0] != cls.heap.address_size:
                    continue

                ref_gen = cls.heap.relative_offsets_by_index(
                    cls.view.read_int(class_hub_addr + offset, 4, True),
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

        class_type_builder.outref_offsets = set(
            cls.heap.relative_offsets_by_index(class_hub['referenceMapIndex'])
        )
        string_hub = cls.heap.read_pointer(class_hub['name'])
        companion_hub = cls.heap.read_pointer(class_hub['companion'])

        is_closed = False
        for offset in class_type_builder.outref_offsets:
            if class_type_builder.is_covered(offset, cls.heap.address_size):
                continue

            if (slots := cls.heap.read_pointer(class_hub_addr + offset)) is None:
                continue
            if (int_array_hub := cls.heap.read_pointer(slots)) is None:
                continue
            if (name_of_array := cls.heap.read_pointer(int_array_hub + name_offset)) is None:
                continue

            try:
                if string_type.read_unchecked(name_of_array) != '[I':
                    continue
            except:
                continue

            class_type_builder.add_member_at_offset(
                'openTypeWorldTypeCheckSlots',
                make_object_ptr(cls.view, 'int[]'),
                offset,
            )

            break
        else:
            slot_start = (
                class_type_builder['vtableLength'].offset
                + class_type_builder['vtableLength'].type.width
            )
            slot_end = min(
                m.offset
                for m in class_type_builder.members
                if m.name not in ['vtableLength', 'identityHashCode']
            )

            known_hubs = [
                class_hub,
                class_type_builder.accessor(cls.heap, companion_hub),
                class_type_builder.accessor(cls.heap, string_hub),
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
                if not class_type_builder.is_covered(offset, cls.heap.address_size)
            )
            & class_type_builder.outref_offsets
        )

        if len(potential_component_type_offsets) == 1:
            class_type_builder.add_member_at_offset(
                'componentType',
                make_object_ptr(cls.view, 'java.lang.Class'),
                potential_component_type_offsets[0]
            )
        elif (name_value := cls.heap.read_pointer(class_hub['name'] + string_type.type['value'].offset)) is not None:
            if (byte_array_hub_addr := cls.heap.read_pointer(name_value)) is not None:
                if string_type.read_unchecked(
                    (byte_array_hub := class_type_builder.accessor(cls.heap, byte_array_hub_addr))['name']
                ) == '[B':
                    for offset, byte_hub_addr in byte_array_hub.aligned_refs():
                        if (byte_name := cls.heap.read_pointer(byte_hub_addr + name_offset)) is None:
                            continue

                        try:
                            if string_type.read_unchecked(byte_name) != 'byte':
                                continue
                        except:
                            continue

                        class_type_builder.add_member_at_offset(
                            'componentType',
                            make_object_ptr(cls.view, 'java.lang.Class'),
                            offset,
                        )
                        break

        for offset, flags in class_hub.aligned_ints(2, sign=True):
            if flags != 0x420:
                continue

            class_type_builder.add_member_at_offset(
                'flags',
                TypeBuilder.int(2, True),
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

        companion_size = cls.view.read_int(companion_hub + class_type_builder['layoutEncoding'].offset, 4)
        for offset, monitor_offset in class_type_builder.accessor(cls.heap, companion_hub).aligned_ints(2, sign=True):
            if monitor_offset == 0:
                continue
            if monitor_offset > companion_size - cls.heap.address_size:
                continue
            if monitor_offset % cls.heap.address_size != 0:
                continue

            class_type_builder.add_member_at_offset(
                'monitorOffset',
                TypeBuilder.int(2, True),
                offset,
            )
            break

        def search_classes():
            for addr in cls.heap.find_refs_to(class_hub_addr):
                hub = class_type_builder.accessor(cls.heap, addr)
                if (other_companion := hub['companion']) is None:
                    continue
                if cls.heap.read_pointer(other_companion) != companion_hub:
                    continue

                yield hub

        if is_closed:
            slot_start = (
                class_type_builder['vtableLength'].offset
                + class_type_builder['vtableLength'].type.width
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
                    TypeBuilder.int(2, True),
                    slot_length,
                ),
                slot_start,
            )
        else:
            array_base = class_hub['openTypeWorldTypeCheckSlots'] + cls.heap.address_size + 4 + 4
            known_hubs = [
                class_hub,
                class_type_builder.accessor(cls.heap, companion_hub),
                class_type_builder.accessor(cls.heap, string_hub),
            ]

            type_id_offsets = Counter()
            for hub in known_hubs:
                for offset, type_id in hub.aligned_ints(4):
                    if type_id == 0:
                        continue

                    for depth_offset, depth in class_hub.aligned_ints(2, sign=True):
                        if offset <= depth_offset < (offset + 4):
                            continue
                        if cls.view.read_int(array_base + (depth * 4), 4) != type_id:
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
                TypeBuilder.named_type_reference(
                    NamedTypeReferenceClass.TypedefNamedTypeClass,
                    'org.graalvm.nativeimage.c.function.CFunctionPointer',
                    alignment=cls.heap.address_size,
                    width=cls.heap.address_size,
                ),
                1,
            ),
            array_base_offset,
        )

        cls.type = class_type_builder.immutable_copy()
        cls.hub_address = class_hub_addr

        cls.reconstructed = True
        for stype, addr in cls.lazy_defined_types.items():
            stype.hub_address = addr

        cls.lazy_defined_types = {}

    @classmethod
    def is_instance(cls, hub_addr: int, name: str | None = None, **kwargs):
        metaclass_hub_addr = cls.heap.read_pointer(hub_addr)
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

        from .string import SubstrateString
        string_type = SubstrateString.for_view(cls.heap)
        if cls.reconstructed:
            hub_accessor = cls.typed_data_accessor(hub_addr)
            string = cls.heap.resolve_target(hub_accessor['name'].value)
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
                    make_object_ptr(cls.view, 'java.lang.String'),
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
        from .string import SubstrateString
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

        accessor = cls.typed_data_accessor(address)
        
        if address in (hub_mapping := SubstrateType.get_hub_mapping(cls.view)):
            self.instance_type = hub_mapping[address]
        else:
            if (string := cls.heap.resolve_target(accessor['name'].value)) is None:
                raise ValueError

            from .string import SubstrateString
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
                vtable_start + (accessor['vtableLength'].value * cls.heap.address_size),
                cls.heap.address_size
            )
        ]

class SubstrateClassMeta(ManagedHeapObject, SubstrateType, base_specialisation=SubstrateClass):
    raw_name = 'java.lang.Class'

    array_length_member = 'vtableLength'
    array_base_member = 'vtable'

    reconstructed: bool

    def __init__(cls, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            cls.reconstructed = cls['layoutEncoding'] is not None
        except ValueError:
            cls.reconstructed = False

        cls.lazy_defined_types = {}