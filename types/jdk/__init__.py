from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder
from binaryninja.enums import StructureVariant

from ..builder import ObjectBuilder
from .primitive import primitive_type_definitions
from .bytearray import SubstrateByteArray
from .string import SubstrateString
from .module import module_type_definitions
from .klass import SubstrateClass
from .reflect import reflect_type_definitions

def jdk_type_definitions(view: BinaryView):
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
            module_type_definitions,
			# Dynamically reconstructed, but we need the flags
            SubstrateClass.make_type_definitions,
			reflect_type_definitions,	
		]
		for t in definition_factory(view)
	]

__all__ = ['jdk_type_definitions']