from typing import Generator

class Int4Iterator:
    data: bytes
    pos: int

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def __iter__(self):
        return self
    
    def __len__(self):
        return (len(self.data) - self.pos) // 4
        
    def __next__(self) -> int:
        if self.pos + 4 > len(self.data):
            raise StopIteration
        
        res = int.from_bytes(
            self.data[self.pos:self.pos+4],
            'little',
            signed=True,
        )

        self.pos += 4

        return res


def decode_reference_map(
    encoding: bytes | bytearray | Int4Iterator,
    *,
    reference_size: int = 8
) -> Generator[int]:
    if not isinstance(encoding, Int4Iterator):
        encoding = Int4Iterator(encoding)

    try:
        num_entries = next(encoding)
    except StopIteration:
        raise ValueError('Truncated data') from e

    try:
        for _ in range(num_entries):
            base_offset = next(encoding)
            for i in range(next(encoding)):
                yield base_offset + (i * reference_size)
    except StopIteration as e:
        raise ValueError('Truncated data') from e

def decode_all_reference_maps(
    encoding: bytes,
    *,
    reference_size: int = 8
) -> dict[int, list[int]]:
    reference_map = {}

    ints = Int4Iterator(encoding)
    while ints:
        index = ints.pos
        if (offsets := decode_reference_map(ints, reference_size=reference_size)) is None:
            return reference_map

        reference_map[index] = offsets

