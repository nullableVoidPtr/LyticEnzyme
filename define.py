from binaryninja import Type, BackgroundTask
from .log import logger
from ._types.meta import SubstrateType
from ._types.layout_encoding import PureInstanceLayout
from .heap import SvmHeap

def recursively_define(heap: SvmHeap, addrs: list[int], *, task: BackgroundTask | None = None):
    defined_vars = 0

    chunk_starts = set()
    chunk_addr = heap.start
    while chunk_addr is not None:
        header_type = heap.view.get_type_by_name('com.oracle.svm.core.genscavenge.HeapChunk$Header')
        assert header_type is not None
        accessor = heap.view.typed_data_accessor(
            chunk_addr,
            header_type,
        )

        heap.view.define_data_var(
            chunk_addr,
            Type.named_type_from_registered_type(
                heap.view,
                'com.oracle.svm.core.genscavenge.AlignedHeapChunk$AlignedHeader',
            ),
        )
        defined_vars += 1

        if (next_offset := int(accessor['OffsetToNextChunk'])) == 0:
            if (next_offset := int(accessor['EndOffset'])) == 0:
                break
        
        chunk_starts.add(chunk_addr)

        chunk_addr += next_offset

    visited = set()
    queue = addrs.copy()

    while queue and not getattr(task, 'cancelled', False):
        if task:
            task.progress = f"Analysing SVM heap ({defined_vars}/{defined_vars + len(queue)})"

        if (current := queue.pop(0)) in visited:
            continue

        visited.add(current)
        if current in chunk_starts:
            continue

        if (hub := heap.read_pointer(current)) is None:
            continue

        class_type = SubstrateType.from_hub(heap, hub)
        if class_type is None:
            continue
        
        assert class_type.hub_address is not None
        queue.append(class_type.hub_address)
        if class_type.component_type is not None:
            assert class_type.component_type.hub_address is not None
            queue.append(class_type.component_type.hub_address)

        data_type = class_type.registered_name

        name = None

        definite_width = True
        if class_type.name == 'java.lang.Class':
            if stype := SubstrateType.from_hub(heap, current):
                name = stype.name + '.class'

            data_type = class_type.derive_type(current)
        elif class_type.is_simple_array:
            data_type = class_type.derive_type(current)
        elif not isinstance(class_type.layout, PureInstanceLayout):
            definite_width = False

        heap.view.define_data_var(current, data_type, name)
        defined_vars += 1

        for ref in class_type.references_from(current):
            queue.append(ref)

        for ref in heap.find_refs_from(current):
            queue.append(ref)

        if definite_width:
            next_object = current + data_type.width
            aligned_next_object = next_object + (-next_object % heap.address_size)
            queue.append(aligned_next_object)


    logger.log_info(f"Defined {defined_vars} heap objects")
