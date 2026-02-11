from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder, NamedTypeReferenceType, StructureBuilder, StructureMember, BaseStructure, QualifiedName, QualifiedNameType, EnumerationType, EnumerationBuilder, PointerType
from binaryninja.enums import StructureVariant, NamedTypeReferenceClass

from abc import ABC
from typing import Sequence, Final
from enum import Enum

class LyticTypeBuilder(ABC):
    view: BinaryView
    name: QualifiedName
    _builder: TypeBuilder

    ntr_class: NamedTypeReferenceClass

    def __init__(self, view: BinaryView, name: QualifiedNameType, builder: TypeBuilder):
        self.view = view
        if not isinstance(name, QualifiedName):
            name = QualifiedName(name)
        self.name = name
        self._builder = builder

    @property
    def registered_name(self):
        return TypeBuilder.named_type_reference(
            self.ntr_class,
            self.name,
            width=self.width,
        )

    @property
    def width(self) -> int:
        return self._builder.width

    def mutable_copy(self) -> TypeBuilder:
        return self._builder.mutable_copy()

    def immutable_copy(self) -> Type:
        return self._builder.immutable_copy()
    
    @staticmethod
    def named_typedef(name: QualifiedNameType, *args, **kwargs) -> NamedTypeReferenceType:
        if not isinstance(name, QualifiedName):
            name = QualifiedName(name)

        return TypeBuilder.named_type_reference(
            NamedTypeReferenceClass.TypedefNamedTypeClass,
            name,
            *args,
            **kwargs,
        )

    @staticmethod
    def named_enum(name: QualifiedNameType, *args, **kwargs) -> NamedTypeReferenceType:
        if not isinstance(name, QualifiedName):
            name = QualifiedName(name)

        return TypeBuilder.named_type_reference(
            NamedTypeReferenceClass.EnumNamedTypeClass,
            name,
            *args,
            **kwargs,
        )

    @staticmethod
    def object_pointer(view: BinaryView, name: QualifiedNameType) -> PointerType:
        assert view.arch is not None

        if not isinstance(name, QualifiedName):
            name = QualifiedName(name)

        return TypeBuilder.pointer(
            view.arch,
            TypeBuilder.named_type_reference(
                NamedTypeReferenceClass.ClassNamedTypeClass,
                name,
            ),
        )

class ObjectBuilder(LyticTypeBuilder):
    _builder: Final[StructureBuilder]

    ntr_class = NamedTypeReferenceClass.ClassNamedTypeClass

    def __init__(
        self,
        view: BinaryView,
        name: QualifiedNameType,
        members: Sequence[tuple[LyticTypeBuilder | Type | TypeBuilder | str, str] | StructureMember] | None = None,
        *,
        hub_address: int | None = None,
        base: 'ObjectBuilder | None' = None,
        raw_structure: bool = False,
        structure_type: StructureVariant | None = None,
    ):
        assert view.arch is not None

        super().__init__(
            view,
            name,
            StructureBuilder.structure(
                type=structure_type or (
                    StructureVariant.StructStructureType
                    if raw_structure else
                    StructureVariant.ClassStructureType
                )
            )
        )

        self._builder.attributes["LyticEnzyme.Hub"] = 'unknown' if hub_address is None else hex(hub_address)

        if raw_structure or structure_type is not None:
            match self._builder.type:
                case StructureVariant.ClassStructureType:
                    self.ntr_class = NamedTypeReferenceClass.ClassNamedTypeClass
                case StructureVariant.StructStructureType:
                    self.ntr_class = NamedTypeReferenceClass.StructNamedTypeClass
                case StructureVariant.UnionStructureType:
                    self.ntr_class = NamedTypeReferenceClass.UnionNamedTypeClass

        if not base:
            if not raw_structure:
                self._builder.base_structures = [
                    BaseStructure(
                        Type.named_type_reference(
                            NamedTypeReferenceClass.ClassNamedTypeClass,
                            'java.lang.Object'
                        ),
                        offset=0,
                        width=view.arch.address_size,
                    )
                ]
        else:
            self._builder.base_structures = [
                BaseStructure(
                    Type.named_type_reference(
                        NamedTypeReferenceClass.ClassNamedTypeClass,
                        base.name
                    ),
                    offset=0,
                    width=base.width,
                )
            ]

        if members:
            for member in members:
                if isinstance(member, tuple):
                    self.append(*member)
                elif isinstance(member, StructureMember):
                    self.add_member_at_offset(
                        member.name,
                        member.type,
                        member.offset,
                    )

    def append(self, _type: LyticTypeBuilder | Type | TypeBuilder | str, name: str = ""):
        assert self.view.arch is not None

        if isinstance(_type, ObjectBuilder):
            _type = TypeBuilder.pointer(
                self.view.arch,
                _type.registered_name,
            )
        elif isinstance(_type, LyticTypeBuilder):
            _type = _type.registered_name
        elif isinstance(_type, str):
            _type = TypeBuilder.pointer(
                self.view.arch,
                TypeBuilder.named_type_reference(
                    NamedTypeReferenceClass.ClassNamedTypeClass,
                    QualifiedName(_type),
                ),
            )

        self._builder.append(
            _type,
            name,
        )

    def add_member_at_offset(self, name: str | None, _type: LyticTypeBuilder | Type | TypeBuilder | str, offset: int, **kwargs):
        assert self.view.arch is not None

        if isinstance(_type, ObjectBuilder):
            _type = TypeBuilder.pointer(
                self.view.arch,
                _type.registered_name,
            )
        elif isinstance(_type, LyticTypeBuilder):
            _type = _type.registered_name
        elif isinstance(_type, str):
            _type = TypeBuilder.pointer(
                self.view.arch,
                TypeBuilder.named_type_reference(
                    NamedTypeReferenceClass.ClassNamedTypeClass,
                    QualifiedName(_type),
                ),
            )

        self._builder.add_member_at_offset(
            name or "",
            _type,
            offset,
            **kwargs,
        )

    def __getitem__(self, name: str):
        return self._builder[name]

    @property
    def members(self):
        return self._builder.members

    @property
    def width(self) -> int:
        return self._builder.width
    
    @width.setter
    def width(self, width: int):
        self._builder.width = width

class TypedefBuilder(LyticTypeBuilder):
    ntr_class = NamedTypeReferenceClass.TypedefNamedTypeClass

    def __init__(self, view: BinaryView, name: QualifiedNameType, _type: Type | TypeBuilder, *, hub_address: int | None = None):
        super().__init__(view, name, _type.mutable_copy())

        self._builder.attributes["LyticEnzyme.Hub"] = 'unknown' if hub_address is None else hex(hub_address)

class EnumBuilder(LyticTypeBuilder):
    _builder: Final[EnumerationBuilder]

    ntr_class = NamedTypeReferenceClass.EnumNamedTypeClass

    def __init__(self, view: BinaryView, name: QualifiedNameType, enum: EnumerationType | EnumerationBuilder | type[Enum], *, width: int | None = None):
        if isinstance(enum, (EnumerationType, EnumerationBuilder)):
            builder = enum.mutable_copy()
        else:
            builder = TypeBuilder.enumeration(
                view.arch,
                [
                    (name, value.value)
                    for name, value in enum.__members__.items()
                ],
                width=width,
            )

        super().__init__(view, name, builder)