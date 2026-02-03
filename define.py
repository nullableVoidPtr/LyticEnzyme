from .log import logger
from .types.meta import SubstrateType
from .heap import SvmHeap

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from . import AnalysisTask

def recursively_define(heap: SvmHeap, addrs: list[int], *, task: 'AnalysisTask' | None = None):
    view = heap.view

    visited = set()
    queue = addrs.copy()

    defined_vars = 0
    while queue and not getattr(task, 'cancelled', False):
        if task:
            task.progress = f"Analysing SVM heap ({defined_vars}/{defined_vars + len(queue)})"

        if (current := queue.pop(0)) in visited:
            continue

        visited.add(current)
        if (hub := heap.read_pointer(current)) is None:
            continue

        class_type = SubstrateType.from_hub(heap, hub)
        if class_type is None:
            continue
        
        queue.append(class_type.hub_address)
        if class_type.component_type is not None:
            queue.append(class_type.component_type.hub_address)

        data_type = class_type.registered_name

        name = None

        if class_type.name == 'java.lang.Class':
            if stype := SubstrateType.from_hub(heap, current):
                name = stype.name + '.class'

            data_type = class_type.derive_type(current)
            next_object = current + data_type.width
            aligned_next_object = next_object + (-next_object % heap.view.arch.address_size)
            queue.append(aligned_next_object)
        elif class_type.is_simple_array:
            data_type = class_type.derive_type(current)
            next_object = current + data_type.width
            aligned_next_object = next_object + (-next_object % heap.view.arch.address_size)
            queue.append(aligned_next_object)
        elif class_type.layout and class_type.layout.is_pure_instance:
            next_object = current + data_type.width
            aligned_next_object = next_object + (-next_object % heap.view.arch.address_size)
            queue.append(aligned_next_object)

        view.define_data_var(current, data_type, name)
        defined_vars += 1

        for ref in class_type.references_from(current):
            queue.append(ref)

        for ref in heap.find_refs_from(current):
            queue.append(ref)

    logger.log_info(f"Defined {defined_vars} heap objects")
