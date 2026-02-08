class EncodingReader:
    """Helper to read various integer types from byte arrays"""
    data: bytes
    pos: int

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def read_int(self, width: int, *, signed: bool = False) -> int:
        if self.pos + width > len(self.data):
            raise StopIteration
        
        value = int.from_bytes(self.data[self.pos:self.pos+width], 'little', signed=signed)
        self.pos += width
        return value

    def read_varint(self, *, signed: bool = False) -> int:
        if (result := self.read_int(1)) >= 0xc0:
            shift = 6
            for i in range(2, 12):
                b = self.read_int(1)
                result += b << shift
                if b < 0xc0 or i == 11:
                    break
                shift += 6

        if signed:
            result = (result >> 1) ^ -(result & 1)

        return result


class IntIterator(EncodingReader):
    signed: bool

    def __init__(self, data: bytes, signed: bool = False):
        super().__init__(data)
        self.signed = signed

    def __iter__(self):
        return self
    
    def __len__(self):
        return (len(self.data) - self.pos) // 4

    def __next__(self) -> int:
        return self.read_int(4, signed=self.signed)
