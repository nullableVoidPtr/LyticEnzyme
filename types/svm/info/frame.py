from typing import TYPE_CHECKING
from dataclasses import dataclass

from ....reader import EncodingReader

if TYPE_CHECKING:
    from . import ImageCodeInfo, MethodInfo

ENCODED_BCI_SHIFT = 2
ENCODED_BCI_ADDEND = 4
ENCODED_BCI_DURING_CALL_MASK = 0b10
ENCODED_BCI_RETHROW_EXCEPTION_MASK = 0b01
ENCODED_BCI_NO_CALLER = ENCODED_BCI_DURING_CALL_MASK | ENCODED_BCI_RETHROW_EXCEPTION_MASK

@dataclass
class FrameInfo:
    method_id: int
    line_no: int
    bytecode_index: int
    during_call: bool
    rethrow_exception: bool

    method: MethodInfo | None = None
    deopt_method: int | None = None

    num_locals: int | None = None
    num_stacks: int | None = None
    num_locks: int | None = None

    @staticmethod
    def decode_values(reader: EncodingReader):
        # TODO
        num_value_infos = reader.read_varint()
        for _ in range(num_value_infos):
            flags = reader.read_int(1)
            value_type = flags & 0x07
            if value_type in [1, 2, 3, 4, 6, 7]:  # Types with data
                yield reader.get_sv()

    @staticmethod
    def decode_bytecode_index(encoded_bci: int) -> dict:
        return {
            'bytecode_index': (encoded_bci >> ENCODED_BCI_SHIFT) - ENCODED_BCI_ADDEND,
            'during_call': bool(encoded_bci & ENCODED_BCI_DURING_CALL_MASK),
            'rethrow_exception': bool(encoded_bci & ENCODED_BCI_RETHROW_EXCEPTION_MASK),
        }

    @classmethod
    def parse_uncompressed_slice(cls, reader: EncodingReader, *, info: 'ImageCodeInfo' | None = None):
        while (encoded_bci := reader.read_varint(signed=True)) != ENCODED_BCI_NO_CALLER:
            # TODO: use in function analysis
            num_locks = reader.read_varint()
            num_locals = reader.read_varint()
            num_stack = reader.read_varint()
            deopt_method_index = reader.read_varint(signed=True)

            cls.decode_values(reader)

            method_id = reader.read_varint(signed=True)
            method = None
            if info:
                method_id += info.method_table_first_id
                if method_id != 0:
                    method = info.method_table[method_id]

            line_no = reader.read_varint(signed=True)

            yield cls(
                method_id=method_id,
                line_no=line_no,
                **cls.decode_bytecode_index(encoded_bci),
                method=method,
                deopt_method_index=deopt_method_index,
                num_locals=num_locals,
                num_stack=num_stack,
                num_locks=num_locks,
            )


    @classmethod
    def parse_slice(cls, reader: EncodingReader, *, info: 'ImageCodeInfo' | None = None):
        if (first_value := reader.read_varint(signed=True)) == -1: # UNCOMPRESSED_FRAME_SLICE_MARKER
            yield from cls.parse_uncompressed_slice(reader, info=info)

        successor = None
        first = True
        while True:
            saved_pos = None

            if successor is not None:
                saved_pos = reader.pos
                reader.pos = successor

            if not first:
                first_value = reader.read_varint(signed=True)

            if first_value < 0:
                after_shared = reader.pos
                reader.pos = -(first_value + 2) # COMPRESSED_FRAME_POINTER_ADDEND

                method_id = reader.read_varint(signed=True)
                encoded_source_line = reader.read_varint(signed=True)
                compressed_bci = reader.read_varint(signed=True)

                reader.pos = after_shared
            else:
                method_id = first_value
                encoded_source_line = reader.read_varint(signed=True)
                compressed_bci = reader.read_varint(signed=True)

            method = None
            if info:
                method_id += info.method_table_first_id
                if method_id != 0:
                    method = info.method_table[method_id]

            # COMPRESSED_SOURCE_LINE_ADDEND
            line_no = abs(encoded_source_line) - 3

            if compressed_bci < 0:
                encoded_bci = -(compressed_bci + 1) # COMPRESSED_UNIQUE_SUCCESSOR_ADDEND
                successor = reader.read_varint(signed=True)
            else:
                encoded_bci = compressed_bci
                successor = None

            # Restore position if we jumped to a shared frame
            if saved_pos is not None:
                reader.pos = saved_pos

            yield FrameInfo(
                method_id=method_id,
                line_no=line_no,
                **cls.decode_bytecode_index(encoded_bci),
                method=method,
            )

            if encoded_source_line < 0:
                break

            first = False
