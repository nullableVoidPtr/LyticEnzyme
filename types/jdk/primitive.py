from binaryninja import BinaryView, Endianness
from binaryninja.types import Type, TypeBuilder

def primitive_type_definitions(_: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
    jboolean = TypeBuilder.bool()
    jboolean.attributes['LyticEnzyme.Hub'] = 'unknown'
    jbyte = TypeBuilder.char()
    jbyte.attributes['LyticEnzyme.Hub'] = 'unknown'
    jchar = TypeBuilder.int(2, False)
    jchar.attributes['LyticEnzyme.Hub'] = 'unknown'
    jshort = TypeBuilder.int(2, True) 
    jshort.attributes['LyticEnzyme.Hub'] = 'unknown'
    jint = TypeBuilder.int(4, True) 
    jint.attributes['LyticEnzyme.Hub'] = 'unknown'
    jlong = TypeBuilder.int(8, True) 
    jlong.attributes['LyticEnzyme.Hub'] = 'unknown'
    jfloat = TypeBuilder.float(4) 
    jfloat.attributes['LyticEnzyme.Hub'] = 'unknown'
    jdouble = TypeBuilder.float(8) 
    jdouble.attributes['LyticEnzyme.Hub'] = 'unknown'
    jvoid = TypeBuilder.void() 
    jvoid.attributes['LyticEnzyme.Hub'] = 'unknown'

    return [
        ('jboolean', jboolean),
        ('jbyte', jbyte),
        ('jchar', jchar),
        ('jshort', jshort),
        ('jint', jint),
        ('jlong', jlong),
        ('jfloat', jfloat),
        ('jdouble', jdouble),
        ('jvoid', jvoid),
    ]