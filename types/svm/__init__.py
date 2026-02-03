from binaryninja import BinaryView
from binaryninja.types import Type, TypeBuilder, StructureBuilder, BaseStructure
from binaryninja.enums import NamedTypeReferenceClass

def create_hub_builder(view: BinaryView, **kwargs) -> StructureBuilder:
    struct = TypeBuilder.class_type()
    struct.base_structures = [
        BaseStructure(
            Type.named_type_reference(
                NamedTypeReferenceClass.ClassNamedTypeClass,
                'java.lang.Object'
            ),
            0,
            view.arch.address_size
        )
    ]
    struct.attributes["LyticEnzyme.Hub"] = kwargs.get("hub_address", "unknown")

    return struct

def svm_type_definitions(view: BinaryView) -> list[tuple[str, Type | TypeBuilder]]:
    from ..jdk.object import make_object_ptr

    func_ptr_holder_struct = create_hub_builder(view)
    func_ptr_holder_struct.append(
        TypeBuilder.named_type_reference(
            NamedTypeReferenceClass.TypedefNamedTypeClass,
            'org.graalvm.nativeimage.c.function.CFunctionPointer',
            width=view.arch.address_size,
        ),
        'functionPointer',
    )

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

    image_code_info_struct = create_hub_builder(view)
    image_code_info_struct.append(
        TypeBuilder.named_type_reference(
            NamedTypeReferenceClass.TypedefNamedTypeClass,
            'org.graalvm.nativeimage.c.function.CFunctionPointer',
            width=view.arch.address_size,
        ),
        'codeStart'
    )
    image_code_info_struct.append(TypeBuilder.int(8, False), 'codeSize')
    image_code_info_struct.append(TypeBuilder.int(8, False), 'dataOffset')
    image_code_info_struct.append(TypeBuilder.int(8, False), 'dataSize')
    image_code_info_struct.append(TypeBuilder.int(8, False), 'codeAndDataMemorySize')
    image_code_info_struct.append(make_object_ptr(view, 'java.lang.Object[]'), 'objectFields')
    image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'codeInfoIndex')
    image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'codeInfoEncodings')
    image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'referenceMapEncoding')
    image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'frameInfoEncodings')
    image_code_info_struct.append(make_object_ptr(view, 'java.lang.Object[]'), 'objectConstants')
    image_code_info_struct.append(make_object_ptr(view, 'java.lang.Class[]'), 'classes')
    image_code_info_struct.append(make_object_ptr(view, 'java.lang.String[]'), 'memberNames')
    image_code_info_struct.append(make_object_ptr(view, 'java.lang.String[]'), 'otherStrings')
    image_code_info_struct.append(make_object_ptr(view, 'byte[]'), 'methodTable')
    image_code_info_struct.append(TypeBuilder.int(4, True), 'methodTableFirstId')

    interned_strings_struct = create_hub_builder(view)
    interned_strings_struct.append(make_object_ptr(view, 'java.lang.String[]'), 'imageInternedStrings')

    runtime_metadata_struct = create_hub_builder(view)
    runtime_metadata_struct.append(make_object_ptr(view, 'byte[]'), 'encoding')

    hub_support_struct = create_hub_builder(view)
    hub_support_struct.append(make_object_ptr(view, 'byte[]'), 'referenceMapEncoding')

    return [
        (
            'org.graalvm.nativeimage.c.function.CFunctionPointer',
            TypeBuilder.pointer(view.arch, TypeBuilder.void()),
        ),
        ('com.oracle.svm.core.FunctionPointerHolder', func_ptr_holder_struct),
        (
            'org.graalvm.nativeimage.IsolateThread',
            TypeBuilder.pointer(view.arch, TypeBuilder.void()),
        ),
        ('com.oracle.svm.core.classinitialization.ClassInitializationInfo', class_init_struct),
        ('com.oracle.svm.core.hub.DynamicHub$ReflectionMetadata', reflection_metadata),
        ('com.oracle.svm.core.hub.DynamicHubCompanion', companion_struct),
        ('com.oracle.svm.core.code.ImageCodeInfo', image_code_info_struct),
        ('com.oracle.svm.core.jdk.ImageInternedStrings', interned_strings_struct),
        ('com.oracle.svm.core.code.RuntimeMetadataEncoding', runtime_metadata_struct),
        ('com.oracle.svm.core.hub.DynamicHubSupport', hub_support_struct),
    ]

__all__ = ['create_hub_builder', 'svm_type_definitions']