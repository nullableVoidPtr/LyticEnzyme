from binaryninja import BinaryView, Type, DataRenderer, TypeContext, InstructionTextToken, InstructionTextTokenType, DisassemblyTextLine
from binaryninja.types import NamedTypeReferenceType
from ..heap import SvmHeap
from ..types import is_pointer_to_java_type
from ..types.jdk.string import read_string

def with_annotation(*components: list[list[InstructionTextToken]]):
    inner = []
    for i, l in enumerate(components):
        inner += l
        if i < len(components) - 1:
            inner.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))

    return [
        InstructionTextToken(InstructionTextTokenType.TextToken, ' '),
        InstructionTextToken(InstructionTextTokenType.AnnotationToken, '{'),
        *inner,
        InstructionTextToken(InstructionTextTokenType.AnnotationToken, '}'),
    ]

def with_heap_offset(relative: int, *components: list[list[InstructionTextToken]]):
    return with_annotation([
        InstructionTextToken(InstructionTextTokenType.ExternalSymbolToken, '__svm_heap_base'),
        InstructionTextToken(InstructionTextTokenType.OperationToken, ' + '),
        InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(relative), relative),
    ], *components)

class SvmHeapRenderer(DataRenderer):
    def __init__(self):
        DataRenderer.__init__(self)

    def perform_is_valid_for_data(self, _, view: BinaryView, addr: int, type: Type, _context: TypeContext):
        if not is_pointer_to_java_type(view, type):
            return False

        heap = SvmHeap.for_view(view)
        if not (heap.start <= addr <= heap.end):
            return False

        return True

    def perform_get_lines_for_data(self, _, view: BinaryView, addr: int, _type: Type, prefix: list[InstructionTextToken], _width: int, _context: TypeContext):
        heap = SvmHeap.for_view(view)
        if (raw := view.read_pointer(addr)) == 0:
            return [DisassemblyTextLine([
                *prefix,
                InstructionTextToken(
                    InstructionTextTokenType.KeywordToken,
                    "nullptr",
                    raw,
                ),
            ], addr)]

        if (target := heap.resolve_target(raw)) is None:
            return [DisassemblyTextLine([
                *prefix,
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken,
                    hex(raw),
                    raw,
                ),
            ], addr)]

        line = prefix[:]
        if (var := view.get_data_var_at(target)) is not None:
            var_type = var.type
            if isinstance(var_type, NamedTypeReferenceType):
                var_type = var_type.target(view)

            if getattr(var_type.registered_name, 'name', None) == 'java.lang.String' and (string := read_string(heap, target)) is not None:
                line.append(InstructionTextToken(
                    InstructionTextTokenType.StringToken,
                    f'"{string.replace('"', '\\"')}"',
                    address=target,
                ))
                line.append(InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    f'_svm',
                    target,
                ))
            else:
                line.append(InstructionTextToken(
                    InstructionTextTokenType.DataSymbolToken,
                    var.name or f'data_{target:x}',
                    target,
                ))
        else:
            line.append(InstructionTextToken(
                InstructionTextTokenType.IntegerToken,
                hex(target),
                target,
            ))

        line += with_heap_offset(raw)

        return [DisassemblyTextLine(line, addr)]

    def __del__(self):
        pass
