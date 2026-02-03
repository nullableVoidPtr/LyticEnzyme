from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder

from ..svm import create_hub_builder
from .object import make_object_ptr

def module_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
    version_struct = create_hub_builder(view)
    version_struct.append(make_object_ptr(view, 'java.lang.String'), 'version')
    version_struct.append(make_object_ptr(view, 'java.util.List'), 'sequence')
    version_struct.append(make_object_ptr(view, 'java.util.List'), 'pre')
    version_struct.append(make_object_ptr(view, 'java.util.List'), 'build')

    module_desc_struct = create_hub_builder(view)
    module_desc_struct.append(make_object_ptr(view, 'java.lang.String'), 'name')
    module_desc_struct.append(make_object_ptr(view, 'java.lang.module.ModuleDescriptor$Version'), 'version')
    module_desc_struct.append(make_object_ptr(view, 'java.lang.String'), 'rawVersionString')
    module_desc_struct.append(make_object_ptr(view, 'java.util.Set'), 'modifiers')
    module_desc_struct.append(make_object_ptr(view, 'java.util.Set'), 'requires')
    module_desc_struct.append(make_object_ptr(view, 'java.util.Set'), 'exports')
    module_desc_struct.append(make_object_ptr(view, 'java.util.Set'), 'opens')
    module_desc_struct.append(make_object_ptr(view, 'java.util.Set'), 'uses')
    module_desc_struct.append(make_object_ptr(view, 'java.util.Set'), 'provides')
    module_desc_struct.append(make_object_ptr(view, 'java.util.Set'), 'packages')
    module_desc_struct.append(make_object_ptr(view, 'java.lang.String'), 'mainClass')
    module_desc_struct.append(TypeBuilder.int(4, True), 'hash')
    module_desc_struct.append(TypeBuilder.bool(), 'open')
    module_desc_struct.append(TypeBuilder.bool(), 'automatic')

    module_struct = create_hub_builder(view)
    module_struct.append(make_object_ptr(view, 'java.lang.String'), 'name')
    module_struct.append(make_object_ptr(view, 'java.lang.ClassLoader'), 'loader')
    module_struct.append(make_object_ptr(view, 'java.lang.module.ModuleDescriptor'), 'descriptor')
    module_struct.append(make_object_ptr(view, 'java.util.Set'), 'reads')
    module_struct.append(make_object_ptr(view, 'java.util.Map'), 'openPackages')
    module_struct.append(make_object_ptr(view, 'java.util.Map'), 'exportedPackages')

    return [
        ('java.lang.module.ModuleDescriptor$Version', version_struct),
        ('java.lang.module.ModuleDescriptor', module_desc_struct),
        ('java.lang.Module', module_struct),
    ]
