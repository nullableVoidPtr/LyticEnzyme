from binaryninja import BinaryView
from binaryninja.types import Type, PointerType, NamedTypeReferenceType, StructureType, StructureBuilder

from ..heap import SvmHeap
from .svm import svm_type_definitions
from .jdk import jdk_type_definitions
from .jdk.klass import SubstrateClass
from .meta import SubstrateType

from .parse import get_readable_type_name, parse_method_signature

def get_hub_address_by_name(view: BinaryView, class_name: str, *, no_translate = False):
    if not (hub_type := view.get_type_by_name(class_name if no_translate else get_readable_type_name(class_name))):
        return None

    if (attribute := hub_type.attributes.get("LyticEnzyme.Hub", "unknown")) == 'unknown':
        return None

    try:
        return int(attribute, 16)
    except ValueError:
        return None

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
    'byte[]': '[B'
}

def create_java_types(view: BinaryView):
    known_types = []
    types_list = []
    for factory in [
        jdk_type_definitions,
        svm_type_definitions,
    ]:
        for (s, t) in factory(view):
            types_list.append((s, t.immutable_copy()))
            if 'LyticEnzyme.Hub' in t.attributes:
                known_types.append(s)

    view.define_user_types(
        types_list,
        None,
    )

    for s in known_types:
        SubstrateType.by_name(view, REGISTER_OVERRIDES.get(s, s))

def is_instance_of_type(heap: SvmHeap, addr: int, type_name: str, **kwargs):
    if (class_type := heap.view.get_type_by_name(get_readable_type_name(type_name))):
        if (data_var := heap.view.get_data_var_at(addr)) and data_var.type == class_type:
            return True
    
    if get_hub_address_by_name(heap.view, type_name) == (hub_addr := heap.read_pointer(addr)):
        return True
    
    from .jdk.klass import SubstrateClass
    return SubstrateClass.for_view(heap.view).is_instance(hub_addr, type_name, **kwargs)

def find_instances_by_type_name(heap: SvmHeap, type_name: str):
    if not (hub_addr := SubstrateClass.for_view(heap.view).find_by_name(type_name)):
        return

    for addr in heap.find_refs_to(hub_addr):
        yield addr

def is_object_array(heap: SvmHeap, array: int, element_check):
    view = heap.view

    if (length := view.read_int(array + 0xc, 0x4)) == 0:
        return False

    array_start = array + 0x10
    if not (heap.start <= array_start <= heap.end):
        return False

    array_end = array_start + (view.arch.address_size * length)
    if not (heap.start <= array_end - view.arch.address_size <= heap.end):
        return False

    for current in range(array_start, array_end, view.arch.address_size):
        if (ptr := view.read_pointer(current)) == 0:
            continue

        if (element := heap.resolve_target(ptr)) is False:
            return False

        if not element_check(heap, element):
            return False

    return True

def is_pointer_to_java_type(view: BinaryView, type: Type, name: str | None = None) -> bool:
    if not isinstance(type, PointerType):
        return False
    
    target = type.target
    if isinstance(target, NamedTypeReferenceType):
        # if 'LyticEnzyme.IsObjectPointer' in target.attributes:
        #     return True

        target = target.target(view)

    if not isinstance(target, StructureType) or 'LyticEnzyme.Hub' not in target.attributes:
        return False
    
    if name:
        if target.registered_name.name != name:
            return False
    
    return True
