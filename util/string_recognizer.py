from binaryninja.stringrecognizer import StringRecognizer, CustomStringType
from binaryninja.binaryview import DerivedString, DerivedStringLocation
from binaryninja.enums import DerivedStringLocationType
from binaryninja import HighLevelILFunction, HighLevelILInstruction, Type

from .._types import is_pointer_to_java_type
from .._types.jdk.string import SubstrateString

encoded_string_type = CustomStringType.register("SubstrateVM", "", "_svm")

class SvmStringRecognizer(StringRecognizer):
    recognizer_name = "svm_heap_strings"

    def is_valid_for_type(self, func: HighLevelILFunction, type: Type):
        return is_pointer_to_java_type(func.view, type, 'java.lang.String')

    def recognize_constant_pointer(self, instr: HighLevelILInstruction, type: Type, val: int):
        if not is_pointer_to_java_type(instr.function.view, type, 'java.lang.String'):
            return None

        if (result := SubstrateString.for_view(instr.function.view).read(val)) is None:
            return None

        loc = DerivedStringLocation(DerivedStringLocationType.DataBackedStringLocation, val, len(result) + 3)
        return DerivedString(result, loc, encoded_string_type)