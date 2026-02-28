from binaryninja import BinaryView
from binaryninja.enums import StructureVariant

from typing import Sequence

from ..builder import LyticTypeBuilder, ObjectBuilder
from .primitive import primitive_type_definitions
from .bytearray import SubstrateByteArray
from .string import SubstrateString
from .enum import enum_type_definitions
from .package import package_type_definitions
from .klass import SubstrateClass
from .reflect import reflect_type_definitions

def jdk_type_definitions(view: BinaryView) -> Sequence[LyticTypeBuilder]:
    return [
        ObjectBuilder(
            view,
            'java.lang.Object',
            raw_structure=True,
            structure_type=StructureVariant.ClassStructureType,
            members=[('java.lang.Class', 'hub')]
        )
    ] + [
        t
        for definition_factory in [
            primitive_type_definitions,
            SubstrateByteArray.make_type_definitions,
            SubstrateString.make_type_definitions,
            enum_type_definitions,
            package_type_definitions,
            # Dynamically reconstructed, but we need the flags
            SubstrateClass.make_type_definitions,
            reflect_type_definitions,    
        ]
        for t in definition_factory(view)
    ]

__all__ = ['jdk_type_definitions']