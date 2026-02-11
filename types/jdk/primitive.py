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

class SubstrateBooleanMeta(SubstrateType):
    raw_name = 'boolean'
    name = 'jboolean'

class SubstrateByteMeta(SubstrateType):
    raw_name = 'byte'
    name = 'jbyte'

class SubstrateCharMeta(SubstrateType):
    raw_name = 'char'
    name = 'jchar'

class SubstrateShortMeta(SubstrateType):
    raw_name = 'short'
    name = 'jshort'

class SubstrateIntMeta(SubstrateType):
    raw_name = 'int'
    name = 'jint'

class SubstrateLongMeta(SubstrateType):
    raw_name = 'long'
    name = 'jlong'

class SubstrateFloatMeta(SubstrateType):
    raw_name = 'float'
    name = 'jfloat'

class SubstrateDoubleMeta(SubstrateType):
    raw_name = 'double'
    name = 'jdouble'

class SubstrateVoidMeta(SubstrateType):
    raw_name = 'void'
    name = 'jvoid'