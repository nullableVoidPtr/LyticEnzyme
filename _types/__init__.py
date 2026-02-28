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

def extract_pointer_to_java_type(view: BinaryView, type: Type) -> Type | None:
    if not isinstance(type, PointerType):
        return None

    target = type.target
    if isinstance(target, NamedTypeReferenceType):
        if (target := target.target(view)) is None:
            # raise ValueError
            return None

    if 'LyticEnzyme.Hub' not in target.attributes:
        return None
    
    return target

def is_pointer_to_java_type(view: BinaryView, type: Type, name: str | None = None) -> bool:
    if (target := extract_pointer_to_java_type(view, type)) is None:
        return False

    if not isinstance(target, StructureType) or target.registered_name is None:
        return False

    if name and target.registered_name.name != name:
        return False

    return True
