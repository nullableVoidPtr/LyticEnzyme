from typing import TYPE_CHECKING

from ....reader import EncodingReader
from .frame import FrameInfo

if TYPE_CHECKING:
    from . import ImageCodeInfo

class EntryFlags:
    fs: int
    ex: int
    rm: int
    fi: int

    def __init__(self, flags: int):
        self.fs = flags & 0b11
        flags >>= 2
        self.ex = flags & 0b11
        flags >>= 2
        self.rm = flags & 0b11
        flags >>= 2
        self.fi = flags & 0b11
        flags >>= 2

    @property
    def frame_size_width(self):
        return [0, 1, 2, 4][self.fs]

    @property
    def exception_offset_width(self):
        return [0, 1, 2, 4][self.ex]

    @property
    def reference_map_index_width(self):
        return [0, 0, 2, 4][self.rm]


class CodeInfoEntry:
    ip: int
    offset: int
    flags: int
    
    frame_info: list[FrameInfo]
    frame_info_index: int | None

    DELTA_END_OF_TABLE = 0

    def __init__(self, reader: EncodingReader, ip: int, offset: int, *, info: 'ImageCodeInfo | None' = None):
        self.ip = ip
        self.offset = offset

        self.entry_flags = EntryFlags(reader.read_int(1))

        self.delta_ip = reader.read_int(1)
        if self.delta_ip == CodeInfoEntry.DELTA_END_OF_TABLE:
            self.delta_ip = None

        reader.pos += (
            self.entry_flags.frame_size_width
            + self.entry_flags.exception_offset_width
            + self.entry_flags.reference_map_index_width
        )

        self.frame_info_index = (
            reader.read_int(4, signed=True)
            if self.entry_flags.fi != 0 else
            None
        )

        if self.frame_info_index is not None and info:
            self.frame_info = list(
                FrameInfo.parse_slice(
                    EncodingReader(
                        info.frame_info_encodings,
                        self.frame_info_index,
                    ),
                    info=info,
                )
            )
        else:
            self.frame_info = []

class CodeInfoEntryIterator:
    reader: EncodingReader
    ip: int | None
    kwargs: dict

    def __init__(self, encoding: bytes, ip: int, start_offset: int, **kwargs):
        self.reader = EncodingReader(encoding, start_offset)
        self.ip = ip
        self.kwargs = kwargs

    def __iter__(self):
        return self

    def __next__(self):
        if self.ip is None:
            raise StopIteration

        entry = CodeInfoEntry(
            self.reader,
            self.ip,
            self.reader.pos,
            **self.kwargs,
        )

        if entry.delta_ip is not None:
            self.ip += entry.delta_ip
        else:
            self.ip = None

        return entry
