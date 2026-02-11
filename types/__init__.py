from binaryninja import BinaryView
from binaryninja.types import Type, PointerType, NamedTypeReferenceType, StructureType

from typing import Callable

from ..heap import SvmHeap
from .builder import LyticTypeBuilder
from .svm import svm_type_definitions
from .jdk import jdk_type_definitions
from .meta import SubstrateType

from .parse import get_readable_type_name, parse_method_signature

REGISTER_OVERRIDES = {
    'jboolean': 'boolean',
    'jbyte': 'byte',
    'jchar': 'char',
    'jshort': 'short',
    'jint': 'int',
    'jlong': 'long',
    'jfloat': 'float',
    'jdouble': 'double',
    'jvoid': 'void',
}

def create_java_types(view: BinaryView):
    known_types: list[str] = []
    types_list: list[tuple[str, Type]] = []

    for factory in [
        jdk_type_definitions,
        svm_type_definitions,
    ]:
        for definition in factory(view):
            if isinstance(definition, LyticTypeBuilder):
                name = definition.name
                _type = definition.mutable_copy()
            else:
                name, _type = definition

            if name in view.types:
                if name == 'graal_isolatethread_t':
                    continue
                if name == 'java.lang.Class':
                    # TODO: more rigorous checks
                    continue

            if 'LyticEnzyme.Hub' in _type.attributes:
                if name in view.types:
                    _type.attributes['LyticEnzyme.Hub'] = view.get_type_by_name(name).attributes['LyticEnzyme.Hub']

                known_types.append(str(name))

            types_list.append((name, _type.immutable_copy()))

    view.define_user_types(
        types_list,
        None,
    )

    for name in known_types:
        SubstrateType.by_name(
            view,
            REGISTER_OVERRIDES.get(name, name),
            name if name in REGISTER_OVERRIDES else None,
        )

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
    
    if not target.registered_name:
        return False

    if name and target.registered_name.name != name:
            return False
    
    return True
