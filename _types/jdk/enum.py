from binaryninja import BinaryView
from binaryninja.types import TypeBuilder

from ..builder import ObjectBuilder

def enum_type_definitions(view: BinaryView):
    return [ObjectBuilder(view, 'java.lang.Enum', members=[
        ('java.lang.String', 'name'),
        (TypeBuilder.int(4, True), 'ordinal'),
    ])]