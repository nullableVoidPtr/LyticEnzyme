from binaryninja import StringRecognizer, CustomStringType
from binaryninja import DerivedString, DerivedStringLocation, DerivedStringLocationType
from binaryninja import Function, HighLevelILInstruction, Type

from ..heap import SvmHeap
from ..types import is_pointer_to_java_type
from ..types.jdk.string import read_string

encoded_string_type = CustomStringType.register("SubstrateVM", "", "_svm")

class SvmStringRecognizer(StringRecognizer):
    recognizer_name = "svm_heap_strings"

    def is_valid_for_type(self, func: Function, type: Type):
        return is_pointer_to_java_type(func.view, type, 'java.lang.String')

    def recognize_constant_pointer(self, instr: HighLevelILInstruction, type: Type, val: int):
        if not is_pointer_to_java_type(instr.function.view, type, 'java.lang.String'):
            return None

        result = read_string(SvmHeap.for_view(instr.function.view), val)

        loc = DerivedStringLocation(DerivedStringLocationType.DataBackedStringLocation, val, len(result) + 3)
        return DerivedString(result, loc, encoded_string_type)