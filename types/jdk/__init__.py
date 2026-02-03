from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder

from .primitive import primitive_type_definitions
from .object import make_object_ptr, object_type_definitions
from .bytearray import byte_array_type_definitions
from .string import string_type_definitions
from .module import module_type_definitions
from .klass import SubstrateClass


def jdk_type_definitions(bv: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
	return [
		t
		for definition_factory in [
            object_type_definitions,
			primitive_type_definitions,
			byte_array_type_definitions,
			string_type_definitions,
            module_type_definitions,
            SubstrateClass.make_type_definitions,
		]
		for t in definition_factory(bv)
	]

__all__ = ['make_object_ptr', 'jdk_type_definitions']