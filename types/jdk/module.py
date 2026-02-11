from binaryninja import BinaryView
from binaryninja.types import TypeBuilder

from ..builder import ObjectBuilder

def module_type_definitions(view: BinaryView):
    module_struct = ObjectBuilder(view, 'java.lang.Module', members=[
        ('java.lang.String', 'name'),
        ('java.lang.ClassLoader', 'loader'),
        (module_desc_struct := ObjectBuilder(view, 'java.lang.module.ModuleDescriptor', members=[
            ('java.lang.String', 'name'),
            (version_struct := ObjectBuilder(view, 'java.lang.module.ModuleDescriptor$Version', members=[
                ('java.lang.String', 'version'),
                ('java.util.List', 'sequence'),
                ('java.util.List', 'pre'),
                ('java.util.List', 'build'),
            ]), 'version'),
            ('java.lang.String', 'rawVersionString'),
            ('java.util.Set', 'modifiers'),
            ('java.util.Set', 'requires'),
            ('java.util.Set', 'exports'),
            ('java.util.Set', 'opens'),
            ('java.util.Set', 'uses'),
            ('java.util.Set', 'provides'),
            ('java.util.Set', 'packages'),
            ('java.lang.String', 'mainClass'),
            (TypeBuilder.int(4, True), 'hash'),
            (TypeBuilder.bool(), 'open'),
            (TypeBuilder.bool(), 'automatic'),
        ]), 'descriptor'),
        ('java.util.Set', 'reads'),
        ('java.util.Map', 'openPackages'),
        ('java.util.Map', 'exportedPackages'),
    ])

    return [
        version_struct,
        module_desc_struct,
        module_struct,
    ]
