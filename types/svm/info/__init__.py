from binaryninja import BinaryView, TypedDataAccessor
from binaryninja.types import TypeBuilder

from typing import TYPE_CHECKING, TypeVar, Generator, Callable
from dataclasses import dataclass
from types import new_class
from math import log2, ceil

from ....reader import IntIterator, EncodingReader
from ....heap import SvmHeap
from ...builder import ObjectBuilder
from ...meta import SubstrateType, ManagedTypeByAddress
from .code import CodeInfoEntryIterator

if TYPE_CHECKING:
    from ...jdk.klass import SubstrateClass


@dataclass
class MethodInfo:
    id: int

    klass: SubstrateClass
    method_name: str
    signature: str | None = None
    modifiers: int | None = None

    def __str__(self):
        return self.klass.name + '::' + self.method_name

    def __repr__(self):
        return f"MethodInfo({str(self)})"

def accessor_as_int(accessor: TypedDataAccessor | list[TypedDataAccessor]) -> int:
    assert not isinstance(accessor, list)
    return int(accessor.value)

def get_accessor_for_member(heap: SvmHeap, accessor: TypedDataAccessor, key: str, inner_key: str | None = None) -> TypedDataAccessor:
    if (ptr := heap.resolve_target(accessor_as_int(accessor[key]))) is None:
        raise ValueError
    if (var := heap.view.get_data_var_at(ptr)) is None:
        raise ValueError

    resolved_accessor = heap.view.typed_data_accessor(
        var.address,
        var.type,
    )

    if not inner_key:
        return resolved_accessor
    
    inner_accessor = resolved_accessor[inner_key]
    assert not isinstance(inner_accessor, list)
    return inner_accessor

def get_member_encoding(heap: SvmHeap, accessor: TypedDataAccessor, key: str) -> bytes:
    return bytes(get_accessor_for_member(heap, accessor, key, 'data'))

class ImageCodeInfo:
    heap: SvmHeap # TODO: remove when ABC is defined
    typed_data_accessor: Callable[[int], TypedDataAccessor]

    address: int

    code_start: int
    code_end: int

    code_info_encodings: bytes
    frame_info_encodings: bytes
    index_granularity: int
    code_index: list[int]

    classes: list[SubstrateClass | None]
    method_table: dict[int, MethodInfo]

    @staticmethod
    def make_type_definitions(view: BinaryView):
        assert view.arch is not None

        return [
            ObjectBuilder(view, 'com.oracle.svm.core.code.ImageCodeInfo', members=[
                (ObjectBuilder.named_typedef(
                    'org.graalvm.nativeimage.c.function.CFunctionPointer',
                    width=view.arch.address_size,
                ), 'codeStart'),
                (TypeBuilder.int(8, False), 'codeSize'),
                (TypeBuilder.int(8, False), 'dataOffset'),
                (TypeBuilder.int(8, False), 'dataSize'),
                (TypeBuilder.int(8, False), 'codeAndDataMemorySize'),
                ('java.lang.Object[]', 'objectFields'),
                ('byte[]', 'codeInfoIndex'),
                ('byte[]', 'codeInfoEncodings'),
                ('byte[]', 'referenceMapEncoding'),
                ('byte[]', 'frameInfoEncodings'),
                ('java.lang.Object[]', 'objectConstants'),
                ('java.lang.Class[]', 'classes'),
                ('java.lang.String[]', 'memberNames'),
                ('java.lang.String[]', 'otherStrings'),
                ('byte[]', 'methodTable'),
                (TypeBuilder.int(4, True), 'methodTableFirstId'),
            ]),
        ]

    def __init__(self, address: int):
        cls = type(self)

        self.address = address

        accessor = cls.typed_data_accessor(self.address)

        self.code_start = accessor_as_int(accessor['codeStart'])
        self.code_end = self.code_start + accessor_as_int(accessor['codeSize'])
        self.method_table_first_id = accessor_as_int(accessor['methodTableFirstId'])

        self.code_index = list(IntIterator(
            get_member_encoding(
                cls.heap,
                accessor,
                'codeInfoIndex'
            )
        ))

        self.index_granularity = 2 ** ceil(
            log2(
                (self.code_end - self.code_start) / len(self.code_index)
            ) 
        )

        self.code_info_encodings = get_member_encoding(
            cls.heap,
            accessor,
            'codeInfoEncodings',
        )

        self.frame_info_encodings = get_member_encoding(
            cls.heap,
            accessor,
            'frameInfoEncodings',
        )

        T = TypeVar('T')
        def map_member_array(key: str, transform: Callable[[int], T]) -> Generator[T | None, None, None]:
            for ptr in get_accessor_for_member(
                cls.heap,
                accessor,
                key,
                'data',
            ):
                if (resolved := cls.heap.resolve_target(accessor_as_int(ptr))) is None:
                    yield None
                else:
                    yield transform(resolved)


        from ...jdk.klass import SubstrateClass
        class_type = SubstrateClass.for_view(cls.heap)
        self.classes = list(map_member_array('classes', class_type))

        from ...jdk.string import SubstrateString
        string_type = SubstrateString.for_view(cls.heap)
        member_names: list[str | None] = list(map_member_array('memberNames', string_type.read))
        other_strings: list[str | None] = list(map_member_array('otherStrings', string_type.read))

        encoded_method_table = get_member_encoding(
            cls.heap,
            accessor,
            'methodTable'
        )

        class_index_len = 4 if len(self.classes) >= 0x10000 else 2
        member_index_len = 4 if len(member_names) >= 0x10000 else 2
        signature_index_len = 4 if len(other_strings) >= 0x10000 else 2
        modifier_len = 2

        method_reader = EncodingReader(encoded_method_table)

        if method_reader.read_int(class_index_len) != 0:
            raise ValueError()
        if member_names[method_reader.read_int(member_index_len)] != "":
            raise ValueError()

        encodes_all_metadata = False
        if other_strings[method_reader.read_int(signature_index_len)] == None:
            if method_reader.read_int(modifier_len) == 0xFFFF:
                encodes_all_metadata = True

        if not encodes_all_metadata:
            method_reader.pos = class_index_len + member_index_len

        def read_method_table():
            current_id = 1 + self.method_table_first_id

            while method_reader.pos < len(encoded_method_table):
                try:
                    klass = self.classes[method_reader.read_int(class_index_len)]
                    method_name = member_names[method_reader.read_int(member_index_len)]
                except StopIteration:
                    break

                assert klass is not None 
                assert method_name is not None 

                signature = None
                modifiers = None
                if encodes_all_metadata:
                    if method_reader.pos + signature_index_len + modifier_len >= len(encoded_method_table):
                        raise ValueError()

                    signature = other_strings[method_reader.read_int(signature_index_len)]
                    modifiers = method_reader.read_int(modifier_len)

                yield MethodInfo(
                    current_id,
                    klass,
                    method_name,
                    signature,
                    modifiers,
                )

                current_id += 1

        self.method_table = {
            method.id: method
            for method in read_method_table()
        }

    def lookup_code_info(self, code_addr: int):
        code_offset = self.code_index[
            code_index_index := (code_addr - self.code_start) // self.index_granularity
        ]

        for entry in CodeInfoEntryIterator(
            self.code_info_encodings,
            self.code_start + (code_index_index * self.index_granularity),
            code_offset,
            info=self,
        ):
            if entry.ip == code_addr:
                return entry

            if entry.ip > code_addr:
                break

        return None

    def lookup_method(self, code_addr: int):
        if (entry := self.lookup_code_info(code_addr)) is None:
            return None
        
        if not entry.frame_info:
            return None
        
        return entry.frame_info[-1].method

    @staticmethod
    def for_view(view: BinaryView | SvmHeap):
        return new_class(
            name='ImageCodeInfo',
            kwds={
                'metaclass': ImageCodeInfoMeta,
                'view': view,
            },
            exec_body=None,
        )

class ImageCodeInfoMeta(ManagedTypeByAddress, SubstrateType, base_specialisation=ImageCodeInfo):
    raw_name = 'com.oracle.svm.core.code.ImageCodeInfo'