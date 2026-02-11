from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder, NamedTypeReferenceType, NamedTypeReferenceBuilder

from ..builder import LyticTypeBuilder, ObjectBuilder, TypedefBuilder
from .info import ImageCodeInfo

def svm_type_definitions(view: BinaryView) -> list[LyticTypeBuilder | tuple[str, Type | TypeBuilder]]:
    assert view.arch is not None

    aligned_heap_chunk_header = ObjectBuilder(
        view,
        'com.oracle.svm.core.genscavenge.AlignedHeapChunk$AlignedHeader',
        base=(heap_chunk_header := ObjectBuilder(
            view,
            'com.oracle.svm.core.genscavenge.HeapChunk$Header',
            raw_structure=True,
            members=[
                (TypeBuilder.int(8, False), 'EndOffset'),
                (TypeBuilder.int(8, False), 'IdentityHashSalt'),
                (TypeBuilder.int(8, True), 'OffsetToNextChunk'),
                (TypeBuilder.int(8, True), 'OffsetToPreviousChunk'),
                ('com.oracle.svm.core.genscavenge.Space', 'Space'),
                (TypeBuilder.int(8, False), 'TopOffset'),
                (TypeBuilder.int(4, True), 'PinnedObjectCount'),
            ],
        )),
        members=[(TypeBuilder.bool(), 'ShouldSweepInsteadOfCompact')]
    )

    c_function_ptr = TypedefBuilder(
        view,
        'org.graalvm.nativeimage.c.function.CFunctionPointer',
        TypeBuilder.pointer(view.arch, Type.void())
    )

    func_ptr_holder_struct = ObjectBuilder(
        view,
        'com.oracle.svm.core.FunctionPointerHolder',
        members=[(c_function_ptr, 'functionPointer')]
    )

    isolate_thread_ref = (isolate_thread := ObjectBuilder(view, 'graal_isolatethread_t', raw_structure=True)).registered_name
    assert isinstance(isolate_thread_ref, (NamedTypeReferenceType, NamedTypeReferenceBuilder))
    isolate_thread_ptr = TypedefBuilder(
        view,
        'org.graalvm.nativeimage.IsolateThread',
        TypeBuilder.pointer(
            view.arch,
            isolate_thread_ref,
        )
    )

    companion_struct = ObjectBuilder(view, 'com.oracle.svm.core.hub.DynamicHubCompanion', members=[
        ('java.lang.Module', 'module'),
        ('java.lang.Class', 'superHub'),
        ('java.lang.String', 'sourceFileName'),
        ('java.lang.Class', 'nestHost'),
        ('java.lang.String', 'simpleBinaryName'),
        ('java.lang.Object', 'declaringClass'),
        ('java.lang.String', 'signature'),
        ('java.lang.Class', 'arrayHub'),
        ('java.lang.Object', 'interfacesEncoding'),
        ('java.lang.Object', 'enumConstantsReference'),
        (class_init_struct := ObjectBuilder(view, 'com.oracle.svm.core.classinitialization.ClassInitializationInfo', members=[
            ('com.oracle.svm.core.FunctionPointerHolder', 'classInitializer'),
            ('com.oracle.svm.core.classinitialization.ClassInitializationInfo$TypeReached', 'typeReached'),
            ('com.oracle.svm.core.classinitialization.ClassInitializationInfo$InitState', 'initState'),
            (isolate_thread_ptr, 'initThread'),
            ('java.util.concurrent.locks.ReentrantLock', 'initLock'),
            ('java.util.concurrent.locks.Condition', 'initCondition'),
            (TypeBuilder.bool(), 'slowPathRequired'),
        ]), 'classInitializationInfo'),
        (reflection_metadata := ObjectBuilder(view, 'com.oracle.svm.core.hub.DynamicHub$ReflectionMetadata', members=[
            (TypeBuilder.int(4, True), 'fieldsEncodingIndex'),
            (TypeBuilder.int(4, True), 'methodsEncodingIndex'),
            (TypeBuilder.int(4, True), 'constructorsEncodingIndex'),
            (TypeBuilder.int(4, True), 'classFlags'),
        ]), 'reflectionMetadata'),
        ('com.oracle.svm.core.hub.DynamicHub$DynamicHubMetadata', 'hubMetadata'),
        ('java.lang.Object', 'classLoader'),
        ('java.lang.String', 'packageName'),
        ('sun.reflect.generics.repository.ClassRepository', 'genericInfo'),
        ('java.lang.ref.SoftReference', 'reflectionData'),
        ('sun.reflect.annotation.AnnotationType', 'annotationType'),
        ('java.lang.Class$AnnotationData', 'annotationData'),
        ('java.lang.reflect.Constructor', 'cachedConstructor'),
        (LyticTypeBuilder.named_enum('ReflectionModifiers', width=4), 'modifiers'),
        (TypeBuilder.char(), 'additionalFlags'),
        (TypeBuilder.bool(), 'canUnsafeAllocate'),
    ])

    accessor_struct = ObjectBuilder(view, 'com.oracle.svm.core.reflect.SubstrateAccessor', members=[
        (c_function_ptr, 'expandSignature'),
        (c_function_ptr, 'directTarget'),
        ('java.lang.Class', 'initializeBeforeInvoke')
    ])

    method_accessor_struct = ObjectBuilder(view, 'com.oracle.svm.core.reflect.SubstrateMethodAccessor', base=accessor_struct, members=[
        ('java.lang.Class', 'receiverType'),
        (TypeBuilder.int(4, True), 'vtableIndex'),
        (TypeBuilder.int(4, True), 'interfaceTypeID'),
        (TypeBuilder.bool(), 'callerSensitiveAdapter'),
    ])

    constructor_accessor_struct = ObjectBuilder(view, 'com.oracle.svm.core.reflect.SubstrateConstructorAccessor', base=accessor_struct, members=[
        (c_function_ptr, 'factoryMethodTarget'),
    ])

    return [
        heap_chunk_header,
        aligned_heap_chunk_header,
        c_function_ptr,
        func_ptr_holder_struct,
        isolate_thread,
        isolate_thread_ptr,
        class_init_struct,
        reflection_metadata,
        *ImageCodeInfo.make_type_definitions(view),
        companion_struct,
        ObjectBuilder(view, 'com.oracle.svm.core.jdk.ImageInternedStrings', members=[
            ('java.lang.String[]', 'imageInternedStrings'),
        ]),
        ObjectBuilder(view, 'com.oracle.svm.core.code.RuntimeMetadataEncoding', members=[
            ('byte[]', 'encoding'),
        ]),
        ObjectBuilder(view, 'com.oracle.svm.core.hub.DynamicHubSupport', members=[
            ('byte[]', 'referenceMapEncoding'),
        ]),
        accessor_struct,
        method_accessor_struct,
        constructor_accessor_struct,
    ]

__all__ = ['svm_type_definitions']