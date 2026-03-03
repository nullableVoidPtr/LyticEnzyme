from binaryninja import BinaryView, DataVariable, Function
from binaryninja.types import Symbol
from binaryninja.component import Component
from binaryninja.enums import SymbolType

from typing import ClassVar, Iterator, Union, TypeAlias, overload, TYPE_CHECKING

from .heap import SvmHeapAccessor

if TYPE_CHECKING:
    from ._types.jdk.klass import SubstrateClass

class LazyComponent:
    name: str
    functions: list[Function]
    data_variables: list[DataVariable]

    def __init__(self, name: str):
        self.name = name
        self.data_variables = []
        self.functions = []

    def add_data_variable(self, data_variable: DataVariable):
        self.data_variables.append(data_variable)

    def add_function(self, function: Function):
        self.functions.append(function)

    @overload
    def merge_into(self, component: Component) -> Component: ...
    @overload
    def merge_into(self, component: 'LazyComponent') -> 'LazyComponent': ...

    def merge_into(self, component: 'LazyComponent | Component'):
        for data_variable in self.data_variables:
            component.add_data_variable(data_variable)
        for function in self.functions:
            component.add_function(function)

        return component

    def reify(self, view: BinaryView, parent: str | Component | None = None) -> Component:
        component = view.create_component(
            self.name,
            parent,
        )

        for data_variable in self.data_variables:
            component.add_data_variable(data_variable)
        for function in self.functions:
            component.add_function(function)

        return component

class ModuleComponent:
    _registry: ClassVar[dict[BinaryView, dict[str | None, 'ModuleComponent']]] = {}

    _component: Component
    view: BinaryView
    packages: dict[str, LazyComponent]
    classes: dict['SubstrateClass', LazyComponent]

    package_components: dict[str, Component]
    class_components: dict['SubstrateClass', Component]

    def __init__(self, view: BinaryView, component: Component):
        self._component = component
        self.view = view
        self.packages = {}
        self.classes = {}

        self.package_components = {}
        self.class_components = {}

    @property
    def name(self):
        return self._component.name

    def add_data_variable(self, var: DataVariable):
        self._component.add_data_variable(var)

    def add_package(self, pkg_name: str):
        component = self.packages[pkg_name] = LazyComponent(pkg_name)
        return component

    def add_class(self, klass: 'SubstrateClass'):
        component = self.classes[klass] = LazyComponent(klass.name)
        return component

    def finalise(self):
        package_parents: dict[str, str] = {}

        for package in self.packages.keys():
            if package == '':
                continue

            parts = package.split('.')
            for i in range(len(parts) - 1, 0, -1):
                if (ancestor := ".".join(parts[:i])) in self.packages:
                    package_parents[package] = ancestor
                    break

        for package in sorted(self.packages.values(), key=lambda p: len(p.name)):
            if package.name and package.name != self.name:
                component = package.reify(
                    self.view,
                    (
                        self.package_components[package_parents[package.name]]
                        if package.name in package_parents else
                        self._component
                    ),
                )
            else:
                component = package.merge_into(self._component)

            self.package_components[package.name] = component

        class_parents: dict['SubstrateClass', Component] = {}
        nest_parents: dict['SubstrateClass', 'SubstrateClass'] = {}

        from ._types.jdk.klass import SubstrateClass
        class_type = SubstrateClass.for_view(self.view)
        for klass in self.classes.keys():
            if (component_type := klass.instance_type.component_type):
                component_hub = component_type.hub_address
                assert component_hub is not None

                if (component_type_class := class_type(component_hub)) in self.classes and component_type.array_type == klass.instance_type:
                    nest_parents[klass] = component_type_class
                    continue

            if klass.declaring_class in self.classes:
                nest_parents[klass] = klass.declaring_class
                continue

            parts = klass.name.split('.')
            class_parents[klass] = self._component
            for i in range(len(parts) - 1, 0, -1):
                if (package := '.'.join(parts[:i])) in self.packages:
                    class_parents[klass] = self.package_components[package]
                    break

        for klass, parent in class_parents.items():
            self.class_components[klass] = self.classes[klass].reify(self.view, parent)

        while True:
            missed = False
            for klass, parent in nest_parents.items():
                if klass in self.class_components:
                    continue

                if parent in nest_parents and parent not in self.class_components:
                    missed = True
                    continue

                self.class_components[klass] = self.classes[klass].reify(self.view, self.class_components[parent])

            if not missed:
                break

    @classmethod
    def from_accessor(cls, accessor: SvmHeapAccessor):
        name = accessor['name'].value

        registry = cls._registry.setdefault(view := accessor.view, {})
        if not (component := registry.get(name)):
            component = registry[name] = cls(view, view.create_component(name, view.root_component) if name is not None else view.root_component)

            add_object_symbols(
                accessor,
                f'{name or "$unnamed"}.$module',
                {
                    'name': ['value'],
                    'descriptor': {},
                    'reads': {},
                    'openPackages': {},
                    'exportedPackages': {},
                },
                component=component,
            )

        return component
    
    @classmethod
    def get_all_modules(cls, view: BinaryView) -> Iterator['ModuleComponent']:
        yield from cls._registry.setdefault(view, {}).values()

NameTree: TypeAlias = dict[str, Union["NameTree", list[str]]]

def add_object_symbols(
    accessor: SvmHeapAccessor,
    root_name: str,
    members_to_name: NameTree = {},
    *,
    component: LazyComponent | Component | None = None,
) -> None:
    heap = accessor.heap

    visited: set[int] = set()

    WorkItem: TypeAlias = tuple[str, SvmHeapAccessor, NameTree | list[str]]
    q: list[WorkItem] = [(root_name, accessor, members_to_name)]

    while q:
        name, value, spec = q.pop()

        visited.add(value.address)

        heap.view.define_user_symbol(Symbol(SymbolType.DataSymbol, value.address, name))
        if component and (var := heap.view.get_data_var_at(value.address)):
            component.add_data_variable(var)

        if isinstance(spec, list):
            spec = {m: {} for m in spec}

        for child_key, child_spec in spec.items():
            if not isinstance(child_value := value[child_key].resolve(), SvmHeapAccessor):
                continue

            q.append((f"{name}.{child_key}", child_value, child_spec))