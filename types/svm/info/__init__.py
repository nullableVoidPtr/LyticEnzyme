from binaryninja import BinaryView, TypedDataAccessor
from binaryninja.types import TypeBuilder, NamedTypeReferenceClass

from typing import TYPE_CHECKING
from dataclasses import dataclass
from types import new_class
from math import log2, ceil

from ....reader import IntIterator, EncodingReader
from ....heap import SvmHeap
from ...meta import SubstrateType
from .code import CodeInfoEntryIterator

if TYPE_CHECKING:
    from ...jdk.klass import SubstrateClass


@dataclass
class MethodInfo:
    klass: SubstrateClass
    method_name: str
    signature: str | None = None
    modifiers: int | None = None

    def __str__(self):
        return self.klass.name + '::' + self.method_name

    def __repr__(self):
        return f"MethodInfo({str(self)})"

def get_accessor_for_member(heap: SvmHeap, accessor: TypedDataAccessor, key: str):
    var = heap.view.get_data_var_at(
        heap.resolve_target(accessor[key].value)
    )
    return heap.view.typed_data_accessor(
        var.address,
        var.type,
    )

class ImageCodeInfo:
    address: int

    code_start: int
    code_end: int

    code_info_encodings: bytes
    frame_info_encodings: bytes
    index_granularity: int
    code_index: list[int]

    classes: list[SubstrateClass]
    method_table: dict[int, MethodInfo]

    @staticmethod
    def make_type_definitions(view: BinaryView):
        from .. import create_hub_builder
        from ...jdk.object import make_object_ptr

        image_code_info_struct = create_hub_builder(view)
        image_code_info_struct.append(
            TypeBuilder.named_type_reference(
                NamedTypeReferenceClass.TypedefNamedTypeClass,
                'org.graalvm.nativeimage.c.function.CFunctionPointer',
                width=view.arch.address_size,
            ),
            'codeStart'
        )
        image_code_info_struct.append(TypeBuilder.int(8, False), 'codeSize')
        image_code_info_struct.append(TypeBuilder.int(8, False), 'dataOffset')
        image_code_info_struct.append(TypeBuilder.int(8, False), 'dataSize')
        image_code_info_struct.append(TypeBuilder.int(8, False), 'codeAndDataMemorySize')
        image_code_info_struct.append(make_object_ptr(view, 'java.lang.Object[]'), 'objectFields')
        image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'codeInfoIndex')
        image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'codeInfoEncodings')
        image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'referenceMapEncoding')
        image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'frameInfoEncodings')
        image_code_info_struct.append(make_object_ptr(view, 'java.lang.Object[]'), 'objectConstants')
        image_code_info_struct.append(make_object_ptr(view, 'java.lang.Class[]'), 'classes')
        image_code_info_struct.append(make_object_ptr(view, 'java.lang.String[]'), 'memberNames')
        image_code_info_struct.append(make_object_ptr(view, 'java.lang.String[]'), 'otherStrings')
        image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'methodTable')
        image_code_info_struct.append(TypeBuilder.int(4, True), 'methodTableFirstId')

        return [('com.oracle.svm.core.code.ImageCodeInfo', image_code_info_struct)]

    def __init__(self, address: int):
        self.address = address

        accessor = self.heap.view.typed_data_accessor(
            self.address,
            self.heap.view.get_type_by_name('com.oracle.svm.core.code.ImageCodeInfo'),
        )

        self.code_start = accessor['codeStart'].value
        self.code_end = self.code_start + accessor['codeSize'].value
        self.method_table_first_id = accessor['methodTableFirstId'].value

        self.code_index = list(IntIterator(
            bytes(
                get_accessor_for_member(
                    self.heap,
                    accessor,
                    'codeInfoIndex'
                )['data']
            )
        ))

        self.index_granularity = 2 ** ceil(
            log2(
                (self.code_end - self.code_start) / len(self.code_index)
            ) 
        )

        self.code_info_encodings = bytes(
            get_accessor_for_member(
                self.heap,
                accessor,
                'codeInfoEncodings'
            )['data']
        )

        self.frame_info_encodings = bytes(
            get_accessor_for_member(
                self.heap,
                accessor,
                'frameInfoEncodings'
            )['data']
        )

        from ...jdk.klass import SubstrateClass
        class_type = SubstrateClass.for_view(self.heap)
        self.classes = [
            None
            if (hub := self.heap.resolve_target(ptr)) is None else
            class_type(hub)
            for ptr in get_accessor_for_member(
                self.heap,
                accessor,
                'classes'
            )['data'].value
        ]

        from ...jdk.string import SubstrateString
        string_type = SubstrateString.for_view(self.heap)
        member_names = [
            None
            if (string := self.heap.resolve_target(ptr)) is None else
            string_type.read(string)
            for ptr in get_accessor_for_member(
                self.heap,
                accessor,
                'memberNames'
            )['data'].value
        ]

        other_strings = [
            None
            if (string := self.heap.resolve_target(ptr)) is None else
            string_type.read(string)
            for ptr in get_accessor_for_member(
                self.heap,
                accessor,
                'otherStrings'
            )['data'].value
        ]

        encoded_method_table = bytes(
            get_accessor_for_member(
                self.heap,
                accessor,
                'methodTable'
            )['data']
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
            while method_reader.pos < len(encoded_method_table):
                try:
                    klass = self.classes[method_reader.read_int(class_index_len)]
                    method_name = member_names[method_reader.read_int(member_index_len)]
                except StopIteration:
                    break

                signature = None
                modifiers = None
                if encodes_all_metadata:
                    if method_reader.pos + signature_index_len + modifier_len >= len(encoded_method_table):
                        raise ValueError()

                    signature = other_strings[method_reader.read_int(signature_index_len)]
                    modifiers = method_reader.read_int(modifier_len)

                yield MethodInfo(
                    klass,
                    method_name,
                    signature,
                    modifiers,
                )

        self.method_table = {
            method_id: method
            for method_id, method in enumerate(read_method_table(), start=1 + self.method_table_first_id)
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

class ImageCodeInfoMeta(SubstrateType, base_specialisation=ImageCodeInfo):
    raw_name = 'com.oracle.svm.core.code.ImageCodeInfo'