from binaryninja import BinaryView
from binaryninja.types import TypeBuilder

from enum import IntFlag, auto

from ..builder import ObjectBuilder, EnumBuilder
class ReflectionModifiers(IntFlag):
    PUBLIC = auto()
    PRIVATE = auto()
    PROTECTED = auto()
    STATIC = auto()
    FINAL = auto()
    SYNCHRONIZED = auto()
    VOLATILE = auto()
    TRANSIENT = auto()
    NATIVE = auto()
    INTERFACE = auto()
    ABSTRACT = auto()
    STRICT = auto()
    SYNTHETIC = auto()
    ANNOTATION = auto()
    ENUM = auto()
    MANDATED = auto()


def reflect_type_definitions(view: BinaryView):
    modifiers_enum = EnumBuilder(view, ReflectionModifiers.__name__, ReflectionModifiers)
    
    executable_struct = ObjectBuilder(view, 'java.lang.reflect.Executable')
    executable_struct.add_member_at_offset('declaredAnnotations', 'java.util.Map', 0x28)
    executable_struct.append('byte[]', 'rawParameters')

    method_struct = ObjectBuilder(view, 'java.lang.reflect.Method', base=executable_struct)
    method_struct.add_member_at_offset('callerSensitive', TypeBuilder.char(), 0x21)
    method_struct.add_member_at_offset('slot', TypeBuilder.int(4, True), 0x24)
    method_struct.add_member_at_offset('clazz', 'java.lang.Class', 0x38)
    method_struct.append('java.lang.String', 'name')
    method_struct.append('java.lang.Class', 'returnType')
    method_struct.append('java.lang.Class[]', 'parameterTypes')
    method_struct.append('java.lang.Class[]', 'exceptionTypes')
    method_struct.append('java.lang.String', 'signature')
    method_struct.append('byte[]', 'annotations')
    method_struct.append('byte[]', 'parameterAnnotations')
    method_struct.append('byte[]', 'annotationDefault')
    method_struct.append('java.lang.reflect.Method', 'root')
    method_struct.append('sun.reflect.generics.repository.MethodRepository', 'genericInfo')
    method_struct.append('jdk.internal.reflect.MethodAccessor', 'methodAccessor')
    method_struct.append('jdk.internal.reflect.MethodAccessor', 'methodAccessorFromMetadata')
    method_struct.append(modifiers_enum, 'modifiers')
    method_struct.append(TypeBuilder.int(4, True), 'hash')
    method_struct.append(TypeBuilder.int(4, True), 'layerId')

    constructor_struct = ObjectBuilder(view, 'java.lang.reflect.Constructor', base=executable_struct)
    constructor_struct.add_member_at_offset('slot', TypeBuilder.int(4, True), 0x24)
    constructor_struct.add_member_at_offset('clazz', 'java.lang.Class', 0x38)
    constructor_struct.append('java.lang.Class[]', 'parameterTypes')
    constructor_struct.append('java.lang.Class[]', 'exceptionTypes')
    constructor_struct.append('java.lang.String', 'signature')
    constructor_struct.append('byte[]', 'annotations')
    constructor_struct.append('byte[]', 'parameterAnnotations')
    constructor_struct.append('java.lang.reflect.Constructor', 'root')
    constructor_struct.append('sun.reflect.generics.repository.ConstructorRepository', 'genericInfo')
    constructor_struct.append('jdk.internal.reflect.ConstructorAccessor', 'constructorAccessor')
    constructor_struct.append('jdk.internal.reflect.ConstructorAccessor', 'constructorAccessorFromMetadata')
    constructor_struct.append(modifiers_enum, 'modifiers')

    return [
        modifiers_enum,
        executable_struct,
        method_struct,
        constructor_struct,
    ]