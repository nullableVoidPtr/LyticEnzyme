from binaryninja import BinaryView
from binaryninja.types import TypeBuilder

from ..builder import TypedefBuilder
from ..meta import SubstrateType

def primitive_type_definitions(view: BinaryView):
    return [
        TypedefBuilder(view, name, _type)
        for name, _type in 
        [
            ('jboolean', TypeBuilder.bool()),
            ('jbyte', TypeBuilder.char()),
            ('jchar', TypeBuilder.int(2, False)),
            ('jshort', TypeBuilder.int(2, True)),
            ('jint', TypeBuilder.int(4, True)),
            ('jlong', TypeBuilder.int(8, True)),
            ('jfloat', TypeBuilder.float(4)),
            ('jdouble', TypeBuilder.float(8)),
            ('jvoid', TypeBuilder.void()),
        ]
    ]

class SubstrateBoolean(SubstrateType):
    raw_name = 'boolean'
    name = 'jboolean'

class SubstrateByte(SubstrateType):
    raw_name = 'byte'
    name = 'jbyte'

class SubstrateChar(SubstrateType):
    raw_name = 'char'
    name = 'jchar'

class SubstrateShort(SubstrateType):
    raw_name = 'short'
    name = 'jshort'

class SubstrateInt(SubstrateType):
    raw_name = 'int'
    name = 'jint'

class SubstrateLong(SubstrateType):
    raw_name = 'long'
    name = 'jlong'

class SubstrateFloat(SubstrateType):
    raw_name = 'float'
    name = 'jfloat'

class SubstrateDouble(SubstrateType):
    raw_name = 'double'
    name = 'jdouble'

class SubstrateVoid(SubstrateType):
    raw_name = 'void'
    name = 'jvoid'