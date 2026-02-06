from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder

from .primitive import primitive_type_definitions
from .object import make_object_ptr, object_type_definitions
from .bytearray import SubstrateByteArray
from .string import SubstrateString
from .module import module_type_definitions
from .klass import SubstrateClass


def jdk_type_definitions(bv: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
	return [
		t
		for definition_factory in [
            object_type_definitions,
			primitive_type_definitions,
			SubstrateByteArray.make_type_definitions,
			SubstrateString.make_type_definitions,
            module_type_definitions,
			# Dynamically reconstructed
            # SubstrateClass.make_type_definitions,
		]
		for t in definition_factory(bv)
	]

__all__ = ['make_object_ptr', 'jdk_type_definitions']