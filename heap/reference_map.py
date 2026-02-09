from typing import Generator

from ..reader import IntIterator

# ref: com.oracle.svm.core.heap.InstanceReferenceMapDecoder
def decode_reference_map(
    encoding: bytes | bytearray | IntIterator,
    *,
    reference_size: int = 8
) -> Generator[int]:
    if not isinstance(encoding, IntIterator):
        encoding = IntIterator(encoding, signed=True)

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

    ints = IntIterator(encoding, signed=True)
    while ints:
        index = ints.pos
        if (offsets := decode_reference_map(ints, reference_size=reference_size)) is None:
            return reference_map

        reference_map[index] = offsets
