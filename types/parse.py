from binaryninja.types import TypeBuilder
from binaryninja.enums import NamedTypeReferenceClass

def _parse_type_name(
    type_name: str,
    index = 0,
    *,
    inner: bool = False,
    safe_jni_name: bool | None = None,
):
    safe_jni_name = safe_jni_name or not inner

    if inner:
        match (type_name[index], type_name[index + 1:]):
            case ('Z', _):
                return (
                    'jboolean' if safe_jni_name else 'boolean',
                    index + 1,
                )
            case ('B', _):
                return (
                    'jbyte' if safe_jni_name else 'byte',
                    index + 1,
                )
            case ('C', _):
                return (
                   'jchar' if safe_jni_name else 'char',
                    index + 1,
                )
            case ('S', _):
                return (
                   'jshort' if safe_jni_name else 'short',
                    index + 1,
                )
            case ('I', _):
                return (
                   'jint' if safe_jni_name else 'int',
                    index + 1,
                )
            case ('J', _):
                return (
                   'jlong' if safe_jni_name else 'long',
                    index + 1,
                )
            case ('F', _):
                return (
                   'jfloat' if safe_jni_name else 'float',
                    index + 1,
                )
            case ('D', _):
                return (
                   'jdouble' if safe_jni_name else 'double',
                    index + 1,
                )
            case ('V', _):
                return (
                   'jvoid' if safe_jni_name else 'void',
                    index + 1,
                )
            case ('L', suffix):
                next_index = index + 1 + len(suffix)
                if ';' in suffix:
                    suffix = suffix[:suffix.index(';') + 1]

                return (
                    suffix[:-1].replace('/', '.'),
                    next_index,
                )

    if type_name[index] == '[':
        inner_type, next_index = _parse_type_name(
            type_name,
            index + 1,
            inner=True
        )

        return (inner_type + '[]', next_index)

    return (type_name[index:], len(type_name))

def get_readable_type_name(type_name: str):
    parsed, index = _parse_type_name(type_name, 0)
    if index == len(type_name):
        return parsed
    
    return type_name

def _parse_type_name_as_type(
    type_name: str,
    index = 0,
):
    match (type_name[index], type_name[index + 1:]):
        case ('Z', _):
            return (
                TypeBuilder.bool(),
                index + 1,
            )
        case ('B', _):
            return (
                TypeBuilder.int(1, True),
                index + 1,
            )
        case ('C', _):
            return (
                TypeBuilder.int(2, False),
                index + 1,
            )
        case ('S', _):
            return (
                TypeBuilder.int(2, True),
                index + 1,
            )
        case ('I', _):
            return (
                TypeBuilder.int(4, True),
                index + 1,
            )
        case ('J', _):
            return (
                TypeBuilder.int(8, True),
                index + 1,
            )
        case ('F', _):
            return (
                TypeBuilder.float(4),
                index + 1,
            )
        case ('D', _):
            return (
                TypeBuilder.float(8),
                index + 1,
            )
        case ('V', _):
            return (
                TypeBuilder.void(),
                index + 1,
            )
        case ('L', suffix):
            next_index = index + 1 + len(suffix)
            if ';' in suffix:
                suffix = suffix[:suffix.index(';') + 1]

            return (
                TypeBuilder.named_type_reference(
                    NamedTypeReferenceClass.ClassNamedTypeClass,
                    suffix.replace('/', '.'),
                ),
                next_index,
            )

    if type_name[index] == '[':
        inner_type, next_index = _parse_type_name(
            type_name,
            index + 1,
            inner=True
        )

        return (
            TypeBuilder.named_type_reference(
                NamedTypeReferenceClass.ClassNamedTypeClass,
                inner_type + '[]',
            ),
            next_index,
        )

    raise ValueError()

def _parse_method_signature(type_signature: str):
    if not type_signature.startswith('('):
        return None
    
    func_type = TypeBuilder.function()

    index = 1
    while index < len(type_signature):
        if type_signature[index] == ')':
            return_type, index = _parse_type_name_as_type(
                type_signature,
                index + 1,
            )

            func_type.return_value = return_type
            return func_type, index
        
        param_type, index = _parse_type_name_as_type(
            type_signature,
            index,
        )
        func_type.append(
            param_type  
        )

    raise ValueError()

def parse_method_signature(type_signature: str):
    func_type, index = _parse_method_signature(type_signature, 0)
    if index != len(type_signature):
        raise ValueError()
    
    return func_type