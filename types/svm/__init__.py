from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder, StructureBuilder, BaseStructure
from binaryninja.enums import NamedTypeReferenceClass

from .info import ImageCodeInfo

def create_hub_builder(view: BinaryView, **kwargs) -> StructureBuilder:
    struct = TypeBuilder.class_type()
    struct.base_structures = [
        BaseStructure(
            Type.named_type_reference(
                NamedTypeReferenceClass.ClassNamedTypeClass,
                'java.lang.Object'
            ),
            offset=0,
            width=view.arch.address_size,
        )
    ]
    struct.attributes["LyticEnzyme.Hub"] = kwargs.get("hub_address", "unknown")

    return struct

def svm_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
    from ..jdk.object import make_object_ptr

    heap_chunk_header = TypeBuilder.structure()
    heap_chunk_header.append(TypeBuilder.int(8, False), 'EndOffset')
    heap_chunk_header.append(TypeBuilder.int(8, False), 'IdentityHashSalt')
    heap_chunk_header.append(TypeBuilder.int(8, True), 'OffsetToNextChunk')
    heap_chunk_header.append(TypeBuilder.int(8, True), 'OffsetToPreviousChunk')
    heap_chunk_header.append(make_object_ptr(view, 'com.oracle.svm.core.genscavenge.Space'), 'Space')
    heap_chunk_header.append(TypeBuilder.int(8, False), 'TopOffset')
    heap_chunk_header.append(TypeBuilder.int(4, True), 'PinnedObjectCount')

    aligned_heap_chunk_header = TypeBuilder.structure()
    aligned_heap_chunk_header.base_structures = [
        BaseStructure(
            Type.named_type_reference(
                NamedTypeReferenceClass.StructNamedTypeClass,
                'com.oracle.svm.core.genscavenge.HeapChunk$Header',
            ),
            offset=0,
            width=heap_chunk_header.width,
        ),
    ]
    aligned_heap_chunk_header.append(TypeBuilder.bool(), 'ShouldSweepInsteadOfCompact')

    c_function_ptr = TypeBuilder.pointer(view.arch, TypeBuilder.void())
    c_function_ptr.attributes['LyticEnzyme.Hub'] = 'unknown'

    func_ptr_holder_struct = create_hub_builder(view)
    func_ptr_holder_struct.append(
        TypeBuilder.named_type_reference(
            NamedTypeReferenceClass.TypedefNamedTypeClass,
            'org.graalvm.nativeimage.c.function.CFunctionPointer',
            width=view.arch.address_size,
        ),
        'functionPointer',
    )

    isolate_thread = TypeBuilder.structure()

    isolate_thread_ptr = TypeBuilder.pointer(view.arch, TypeBuilder.named_type_reference(
        NamedTypeReferenceClass.StructNamedTypeClass,
        'graal_isolatethread_t',
        width=view.arch.address_size,
    ))

    class_init_struct = create_hub_builder(view)
    class_init_struct.append(make_object_ptr(view, 'com.oracle.svm.core.FunctionPointerHolder'), 'classInitializer')
    class_init_struct.append(make_object_ptr(view, 'com.oracle.svm.core.classinitialization.ClassInitializationInfo$TypeReached'), 'typeReached')
    class_init_struct.append(make_object_ptr(view, 'com.oracle.svm.core.classinitialization.ClassInitializationInfo$InitState'), 'initState')
    class_init_struct.append(
        TypeBuilder.named_type_reference(
            NamedTypeReferenceClass.TypedefNamedTypeClass,
            'org.graalvm.nativeimage.IsolateThread',
            width=view.arch.address_size,
        ),
        'initThread'
    )
    class_init_struct.append(make_object_ptr(view, 'java.util.concurrent.locks.ReentrantLock'), 'initLock')
    class_init_struct.append(make_object_ptr(view, 'java.util.concurrent.locks.Condition'), 'initCondition')
    class_init_struct.append(TypeBuilder.bool(), 'slowPathRequired')

    reflection_metadata = create_hub_builder(view)
    reflection_metadata.append(TypeBuilder.int(4, True), 'fieldsEncodingIndex')
    reflection_metadata.append(TypeBuilder.int(4, True), 'methodsEncodingIndex')
    reflection_metadata.append(TypeBuilder.int(4, True), 'constructorsEncodingIndex')
    reflection_metadata.append(TypeBuilder.int(4, True), 'classFlags')

    companion_struct = create_hub_builder(view)
    companion_struct.append(make_object_ptr(view, 'java.lang.Module'), 'module')
    companion_struct.append(make_object_ptr(view, 'java.lang.Class'), 'superHub')
    companion_struct.append(make_object_ptr(view, 'java.lang.String'), 'sourceFileName')
    companion_struct.append(make_object_ptr(view, 'java.lang.Class'), 'nestHost')
    companion_struct.append(make_object_ptr(view, 'java.lang.String'), 'simpleBinaryName')
    companion_struct.append(make_object_ptr(view, 'java.lang.Object'), 'declaringClass')
    companion_struct.append(make_object_ptr(view, 'java.lang.String'), 'signature')
    companion_struct.append(make_object_ptr(view, 'java.lang.Class'), 'arrayHub')
    companion_struct.append(make_object_ptr(view, 'java.lang.Object'), 'interfacesEncoding')
    companion_struct.append(make_object_ptr(view, 'java.lang.Object'), 'enumConstantsReference')
    companion_struct.append(make_object_ptr(view, 'com.oracle.svm.core.classinitialization.ClassInitializationInfo'), 'classInitializationInfo')
    companion_struct.append(make_object_ptr(view, 'com.oracle.svm.core.hub.DynamicHub$ReflectionMetadata'), 'reflectionMetadata')
    companion_struct.append(make_object_ptr(view, 'com.oracle.svm.core.hub.DynamicHub$DynamicHubMetadata'), 'hubMetadata')
    companion_struct.append(make_object_ptr(view, 'java.lang.Object'), 'classLoader')
    companion_struct.append(make_object_ptr(view, 'java.lang.String'), 'packageName')
    companion_struct.append(make_object_ptr(view, 'sun.reflect.generics.repository.ClassRepository'), 'genericInfo')
    companion_struct.append(make_object_ptr(view, 'java.lang.ref.SoftReference'), 'reflectionData')
    companion_struct.append(make_object_ptr(view, 'sun.reflect.annotation.AnnotationType'), 'annotationType')
    companion_struct.append(make_object_ptr(view, 'java.lang.Class$AnnotationData'), 'annotationData')
    companion_struct.append(make_object_ptr(view, 'java.lang.reflect.Constructor'), 'cachedConstructor')
    companion_struct.append(TypeBuilder.int(4, True), 'modifiers')
    companion_struct.append(TypeBuilder.char(), 'additionalFlags')
    companion_struct.append(TypeBuilder.bool(), 'canUnsafeAllocate')

    interned_strings_struct = create_hub_builder(view)
    interned_strings_struct.append(make_object_ptr(view, 'java.lang.String[]'), 'imageInternedStrings')

    runtime_metadata_struct = create_hub_builder(view)
    runtime_metadata_struct.append(make_object_ptr(view, 'byte[]'), 'encoding')

    hub_support_struct = create_hub_builder(view)
    hub_support_struct.append(make_object_ptr(view, 'byte[]'), 'referenceMapEncoding')

    return [
        ('com.oracle.svm.core.genscavenge.HeapChunk$Header', heap_chunk_header),
        ('com.oracle.svm.core.genscavenge.AlignedHeapChunk$AlignedHeader', aligned_heap_chunk_header),
        ('org.graalvm.nativeimage.c.function.CFunctionPointer', c_function_ptr),
        ('com.oracle.svm.core.FunctionPointerHolder', func_ptr_holder_struct),
        ('graal_isolatethread_t', isolate_thread),
        ('org.graalvm.nativeimage.IsolateThread', isolate_thread_ptr),
        ('com.oracle.svm.core.classinitialization.ClassInitializationInfo', class_init_struct),
        ('com.oracle.svm.core.hub.DynamicHub$ReflectionMetadata', reflection_metadata),
        *ImageCodeInfo.make_type_definitions(view),
        ('com.oracle.svm.core.hub.DynamicHubCompanion', companion_struct),
        ('com.oracle.svm.core.jdk.ImageInternedStrings', interned_strings_struct),
        ('com.oracle.svm.core.code.RuntimeMetadataEncoding', runtime_metadata_struct),
        ('com.oracle.svm.core.hub.DynamicHubSupport', hub_support_struct),
    ]

__all__ = ['create_hub_builder', 'svm_type_definitions']