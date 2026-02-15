from dataclasses import dataclass
from enum import IntEnum, auto

# ref: com.oracle.svm.core.hub.LayoutEncoding
class LayoutType(IntEnum):
    NEUTRAL = auto()
    PRIMITIVE = auto()
    INTERFACE = auto()
    ABSTRACT = auto()
    PURE_INSTANCE = auto()
    PRIMITIVE_ARRAY = auto()
    OBJECT_ARRAY = auto()
    HYBRID_PRIMITIVE = auto()
    HYBRID_OBJECT = auto()

class ArrayTag(IntEnum):
    PRIMITIVE_ARRAY = 0b111
    HYBRID_PRIMITIVE = 0b110
    OBJECT_ARRAY = 0b101
    HYBRID_OBJECT = 0b100

@dataclass
class LayoutEncoding:
    NEUTRAL_VALUE = 0
    PRIMITIVE_VALUE = 1
    INTERFACE_VALUE = 2
    ABSTRACT_VALUE = 3
    LAST_SPECIAL_VALUE = 3

    ARRAY_INDEX_SHIFT_SHIFT = 0
    ARRAY_INDEX_SHIFT_MASK = 0xff
    ARRAY_BASE_SHIFT = 8
    ARRAY_BASE_MASK = 0xfff
    ARRAY_TAG_BITS = 3
    ARRAY_TAG_SHIFT = 32 - ARRAY_TAG_BITS

    ARRAY_TAG_IDENTITY_BIT = 0b100
    ARRAY_TAG_PRIMITIVE_BIT = 0b010
    ARRAY_TAG_PURE_BIT = 0b001

    raw: int
    layout_type: LayoutType

    @classmethod
    def parse(cls, encoding: int) -> 'LayoutEncoding':
        if encoding > 0x7FFFFFFF:
            encoding = encoding - 0x100000000

        if encoding == cls.NEUTRAL_VALUE:
            return cls(raw=encoding, layout_type=LayoutType.NEUTRAL)
        if encoding == cls.PRIMITIVE_VALUE:
            return cls(raw=encoding, layout_type=LayoutType.PRIMITIVE)
        if encoding == cls.INTERFACE_VALUE:
            return cls(raw=encoding, layout_type=LayoutType.INTERFACE)
        if encoding == cls.ABSTRACT_VALUE:
            return cls(raw=encoding, layout_type=LayoutType.ABSTRACT)

        if encoding > cls.LAST_SPECIAL_VALUE:
            return PureInstanceLayout(
                raw=encoding,
                instance_size=encoding,
                layout_type=PureInstanceLayout.layout_type,
            )

        if encoding < cls.NEUTRAL_VALUE:
            return ArrayLikeLayout.parse(encoding)

        raise ValueError(f"Invalid layout encoding: {encoding}")

    @property
    def is_special(self) -> bool:
        return self.layout_type in (
            LayoutType.NEUTRAL, LayoutType.PRIMITIVE,
            LayoutType.INTERFACE, LayoutType.ABSTRACT
        )

    @property
    def is_primitive(self) -> bool:
        return self.layout_type == LayoutType.PRIMITIVE

    def __str__(self) -> str:
        parts = [f"{self.__class__.__name__}(0x{self.raw & 0xFFFFFFFF:08x}, {self.layout_type.name}"]

        if isinstance(self, PureInstanceLayout):
            parts.append(f", size={self.instance_size}")
        elif isinstance(self, ArrayLikeLayout):
            parts.append(f", base={self.array_base_offset}")
            parts.append(f", shift={self.array_index_shift}")
            parts.append(f", scale={self.array_index_scale}")

        parts.append(")")
        return "".join(parts)

    def __repr__(self) -> str:
        return self.__str__()

@dataclass
class PureInstanceLayout(LayoutEncoding):
    layout_type = LayoutType.PURE_INSTANCE
    instance_size: int

@dataclass
class ArrayLikeLayout(LayoutEncoding):
    array_tag: ArrayTag
    array_base_offset: int
    array_index_shift: int

    @property
    def is_array(self) -> bool:
        return self.layout_type in (LayoutType.PRIMITIVE_ARRAY, LayoutType.OBJECT_ARRAY)

    @property
    def is_hybrid(self) -> bool:
        return self.layout_type in (LayoutType.HYBRID_PRIMITIVE, LayoutType.HYBRID_OBJECT)

    @property
    def is_primitive_array(self) -> bool:
        return self.layout_type == LayoutType.PRIMITIVE_ARRAY

    @property
    def is_object_array(self) -> bool:
        return self.layout_type == LayoutType.OBJECT_ARRAY

    @property
    def has_primitive_elements(self) -> bool:
        return self.layout_type in (LayoutType.PRIMITIVE_ARRAY, LayoutType.HYBRID_PRIMITIVE)

    @property
    def has_object_elements(self) -> bool:
        return self.layout_type in (LayoutType.OBJECT_ARRAY, LayoutType.HYBRID_OBJECT)

    @property
    def array_index_scale(self) -> int:
        return 1 << self.array_index_shift

    def get_array_element_offset(self, index: int) -> int:
        return self.array_base_offset + (index << self.array_index_shift)

    def get_array_size(self, length: int, alignment: int = 8) -> int:
        return (self.get_array_element_offset(length) + alignment - 1) & ~(alignment - 1)

    @classmethod
    def parse(cls, encoding: int) -> 'ArrayLikeLayout':
        if encoding >= cls.NEUTRAL_VALUE:
            raise ValueError('LayoutEncoding is not array-like')

        unsigned = encoding & 0xFFFFFFFF

        tag = (unsigned >> cls.ARRAY_TAG_SHIFT) & 0b111
        base_offset = (encoding >> cls.ARRAY_BASE_SHIFT) & cls.ARRAY_BASE_MASK
        index_shift = (encoding >> cls.ARRAY_INDEX_SHIFT_SHIFT) & cls.ARRAY_INDEX_SHIFT_MASK

        match tag:
            case ArrayTag.PRIMITIVE_ARRAY:
                layout_type = LayoutType.PRIMITIVE_ARRAY
            case ArrayTag.OBJECT_ARRAY:
                layout_type = LayoutType.OBJECT_ARRAY
            case ArrayTag.HYBRID_PRIMITIVE:
                layout_type = LayoutType.HYBRID_PRIMITIVE
            case ArrayTag.HYBRID_OBJECT:
                layout_type = LayoutType.HYBRID_OBJECT
            case _:
                raise ValueError(f"Invalid array tag: {tag:#05b}")

        return cls(
            raw=encoding,
            layout_type=layout_type,
            array_tag=ArrayTag(tag),
            array_base_offset=base_offset,
            array_index_shift=index_shift,
        )
