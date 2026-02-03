from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder
from binaryninja.enums import NamedTypeReferenceClass

def make_object_ptr(view: BinaryView, type_name: str):
    # if not (object_type := view.get_type_by_name(type_name)):
    #     object_type = TypeBuilder.structure()
    #     object_type.attributes["LyticEnzyme.Hub"] = "unknown"
    #     view.define_user_type(type_name, object_type)

    ref = TypeBuilder.named_type_reference(NamedTypeReferenceClass.ClassNamedTypeClass, type_name)
    # ref.attributes['LyticEnzyme.IsObjectPointer'] = ''
    return TypeBuilder.pointer(
        view.arch,
        ref,
    )

def object_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
    object_hub = TypeBuilder.class_type()
    object_hub.append(make_object_ptr(view, 'java.lang.Class'), 'hub')
    object_hub.attributes['LyticEnzyme.Hub'] = 'unknown'
    return [('java.lang.Object', object_hub)]