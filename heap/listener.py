from binaryninja.binaryview import BinaryView, BinaryDataNotification, NotificationType, DataVariable
from binaryninja.types import PointerType, NamedTypeReferenceType

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import SvmHeap

class SvmHeapListener(BinaryDataNotification):
    def __init__(self):
        super(SvmHeapListener, self).__init__(
            NotificationType.NotificationBarrier |
            NotificationType.DataVariableAdded |
            NotificationType.DataVariableLifetime |
            NotificationType.DataVariableRemoved |
            NotificationType.DataVariableUpdated |
            NotificationType.DataVariableUpdates
        )
        self.received_event = False

    def notification_barrier(self, view: BinaryView) -> int:
        has_events = self.received_event
        self.received_event = False

        if has_events:
            return 250

        return 0

    def clear_refs_from_var(self, heap: SvmHeap, var: DataVariable):
        for src in range(var.address, var.address + var.type.width, heap.address_size):
            for dst in heap.view.get_data_refs_from(src):
                heap.view.remove_user_data_ref(src, dst)

    def add_refs_from_var(self, heap: SvmHeap, var: DataVariable):
        resolved = var.type
        if isinstance(resolved, PointerType):
            resolved = resolved.target

        if isinstance(resolved, NamedTypeReferenceType):
            if (resolved := resolved.target(heap.view)) is None:
                return

        if (attribute := resolved.attributes.get("LyticEnzyme.Hub", "unknown")) == 'unknown':
            return

        if heap.instance_reference_map_offset is not None:
            for src, dst in heap.find_refs_from(var.address):
                heap.view.add_user_data_ref(src, dst)

        try:
            hub_address = int(attribute, 16)
        except ValueError:
            return

        from .._types import SubstrateType
        if (stype := SubstrateType.from_hub(heap, hub_address)) is None:
            return

        for src, dst in stype.references_from(var.address):
            heap.view.add_user_data_ref(src, dst)

    def data_var_added(self, view: BinaryView, var: DataVariable) -> None:
        self.received_event = True

        from . import SvmHeap
        heap = SvmHeap.for_view(view)
        self.clear_refs_from_var(heap, var)
        self.add_refs_from_var(heap, var)

    def data_var_updated(self, view: BinaryView, var: DataVariable) -> None:
        self.received_event = True
        
        from . import SvmHeap
        heap = SvmHeap.for_view(view)
        self.clear_refs_from_var(heap, var)
        self.add_refs_from_var(heap, var)

    def data_var_removed(self, view: BinaryView, var: DataVariable) -> None:
        self.received_event = True

        from . import SvmHeap
        heap = SvmHeap.for_view(view)
        self.clear_refs_from_var(heap, var)
