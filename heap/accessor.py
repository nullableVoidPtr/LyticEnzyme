from binaryninja import BinaryView, TypedDataAccessor, Type, types

from typing import TYPE_CHECKING, Any, overload

if TYPE_CHECKING:
    from . import SvmHeap

class SvmHeapAccessor:
    heap: SvmHeap

    _accessor: TypedDataAccessor

    def __init__(self, heap: SvmHeap, addr: int, type: Type):
        self.heap = heap
        self._accessor = self.heap.view.typed_data_accessor(addr, type)

    @property
    def address(self) -> int:
        return self._accessor.address

    @property
    def type(self) -> Type:
        return self._accessor.type

    @property
    def type_target(self) -> Type:
        _type = self.type
        if isinstance(_type, types.NamedTypeReferenceType):
            _type = _type.target(self.view)
            if _type is None:
                raise ValueError(f"Couldn't get target of type {_type}")

        return _type

    @property
    def view(self) -> BinaryView:
        return self.heap.view

    def __len__(self):
        return len(self.type_target)

    def __int__(self):
        return int(self._accessor)

    def resolve(self):
        if (target := self.heap.resolve_target(self)) is None:
            return None

        from .._types import extract_pointer_to_java_type
        if (target_type := extract_pointer_to_java_type(self.view, self.type)) is None:
            raise ValueError('Expected a Substrate type')

        return SvmHeapAccessor(
            self.heap,
            target,
            target_type,
        )

    @overload
    def __getitem__(self, key: str | int) -> 'SvmHeapAccessor': ...

    @overload
    def __getitem__(self, key: slice) -> list['SvmHeapAccessor']: ...

    def __getitem__(self, key: str | int | slice) -> 'SvmHeapAccessor' | list['SvmHeapAccessor']:
        _type = self.type_target

        if isinstance(_type, types.ArrayType):
            match key:
                case int():
                    if key >= _type.count:
                        raise ValueError(f"Index {key} out of bounds array has {_type.count} elements")
                    return SvmHeapAccessor(self.heap, self.address + key * len(_type.element_type), _type.element_type)
                case slice():
                    return [self[i] for i in range(*key.indices(len(self.value)))]

        if not isinstance(_type, types.StructureType):
            raise ValueError("Can't get member of non-structure")

        if not isinstance(key, str):
            raise ValueError("Must use string to get member of structure")

        try:
            member = _type[key]
            offset = member.offset
            _type = member.type.immutable_copy()
        except ValueError:
            if (inherited_member := next((
                member
                for member in 
                _type.members_including_inherited(self.view)
                if member.member.name == key
            ), None)) is None:
                raise ValueError(f"Member {key} doesn't exist in structure")

            offset = inherited_member.base_offset + inherited_member.member.offset
            _type = inherited_member.member.type

        return SvmHeapAccessor(self.heap, self.address + offset, _type)

    @property
    def value(self) -> Any:
        _type = self.type_target

        if isinstance(_type, (types.VoidType, types.FunctionType)):
            return None
        elif isinstance(_type, types.BoolType):
            return bool(self)
        elif isinstance(_type, (types.EnumerationType, types.IntegerType)):
            return int(self)
        elif isinstance(_type, types.PointerType):
            from .._types import extract_pointer_to_java_type
            if (target_type := extract_pointer_to_java_type(self.view, self.type)) is None:
                return int(self)

            if (target := self.heap.resolve_target(self)) is None:
                return None

            try:
                return SvmHeapAccessor(
                    self.heap,
                    target,
                    target_type,
                ).value
            except TypeError:
                return int(self)
        elif isinstance(_type, types.StructureType):
            if (struct_ref := _type.registered_name) is None:
                raise ValueError

            match struct_ref.name:
                case 'java.lang.String':
                    from .._types.jdk.string import SubstrateString
                    return SubstrateString.read(self.address, view=self.heap)
                case 'java.lang.Class':
                    from .._types.jdk.klass import SubstrateClass
                    return SubstrateClass.for_view(self.heap)(self.address)

            raise TypeError(f"Unhandled structure type {_type}")

        raise TypeError(f"Unhandled `Type` {type(_type)}")


