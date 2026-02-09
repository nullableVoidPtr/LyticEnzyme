from binaryninja import BinaryView
from binaryninja.types import Type, PointerType, NamedTypeReferenceType, StructureType

from typing import Callable

from ..heap import SvmHeap
from .svm import svm_type_definitions
from .jdk import jdk_type_definitions
from .meta import SubstrateType

from .parse import get_readable_type_name, parse_method_signature

REGISTER_OVERRIDES = {
    'boolean': 'jboolean',
    'byte': 'jbyte',
    'char': 'jchar',
    'short': 'jshort',
    'int': 'jint',
    'long': 'jlong',
    'float': 'jfloat',
    'double': 'jdouble',
    'void': 'jvoid',
}

def create_java_types(view: BinaryView):
    known_types = []
    types_list = []
    for factory in [
        jdk_type_definitions,
        svm_type_definitions,
    ]:
        for (s, t) in factory(view):
            _type = t.immutable_copy()
            if s in view.types:
                if s == 'graal_isolatethread_t':
                    continue
                if s == 'java.lang.Class':
                    # TODO: more rigorous checks
                    continue

            if 'LyticEnzyme.Hub' in t.attributes:
                if s in view.types:
                    _type.attributes['LyticEnzyme.Hub'] = t.attributes['LyticEnzyme.Hub']

                known_types.append(s)

            types_list.append((s, _type))

    view.define_user_types(
        types_list,
        None,
    )

    for s in known_types:
        SubstrateType.by_name(view, REGISTER_OVERRIDES.get(s, s))

def is_object_array(heap: SvmHeap, array: int, element_check: Callable[bool, [int]]):
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

        if (element := heap.resolve_target(ptr)) is False:
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
    
    if name and target.registered_name.name != name:
            return False
    
    return True
