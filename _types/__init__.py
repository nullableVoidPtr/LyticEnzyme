from binaryninja import BinaryView
from binaryninja.types import Type, PointerType, NamedTypeReferenceType, StructureType, QualifiedName

from typing import Sequence, Callable

from ..heap import SvmHeap
from .builder import LyticTypeBuilder
from .svm import svm_type_definitions
from .jdk import jdk_type_definitions
from .meta import SubstrateType

from .parse import get_readable_type_name, parse_method_signature

def create_java_types(view: BinaryView):
    known_types: list[str] = []
    types_list: list[tuple[QualifiedName, Type]] = []

    for factory in [
        jdk_type_definitions,
        svm_type_definitions,
    ]:
        for definition in factory(view):
            name = definition.name
            _type = definition.mutable_copy()

            if name in view.types:
                if name == 'graal_isolatethread_t':
                    continue
                if name == 'java.lang.Class':
                    # TODO: more rigorous checks
                    continue

            if 'LyticEnzyme.Hub' in _type.attributes:
                try:
                    _type.attributes['LyticEnzyme.Hub'] = view.types[name].attributes['LyticEnzyme.Hub']
                except KeyError:
                    pass

                known_types.append(str(name))

            types_list.append((name, _type.immutable_copy()))

    view.define_user_types(
        types_list,
        None,
    )

    for name in known_types:
        SubstrateType.by_name(view, name)

def is_object_array(heap: SvmHeap, array: int, element_check: Callable[[int], bool]):
    view = heap.view

    if (length := view.read_int(array + 0xc, 0x4)) == 0:
        return False

    array_start = array + 0x10
    if not (heap.start <= array_start <= heap.end):
        return False

    array_end = array_start + (heap.address_size * length)
    if not (heap.start <= array_end - heap.address_size <= heap.end):
        return False

    for current in range(array_start, array_end, heap.address_size):
        if (ptr := view.read_pointer(current)) == 0:
            continue

        if (element := heap.resolve_target(ptr)) is None:
            return False

        if not element_check(element):
            return False

    return True

def is_pointer_to_java_type(view: BinaryView, type: Type, name: str | None = None) -> bool:
    if not isinstance(type, PointerType):
        return False
    
    target = type.target
    if isinstance(target, NamedTypeReferenceType):
        target = target.target(view)

    if not isinstance(target, StructureType) or 'LyticEnzyme.Hub' not in target.attributes:
        return False
    
    if target.registered_name is None:
        return False

    if name and target.registered_name.name != name:
            return False
    
    return True
