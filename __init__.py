from binaryninja import BinaryView, Symbol, Type, FunctionType, FunctionParameter
from binaryninja.callingconvention import CallingConvention
from binaryninja.plugin import PluginCommand, BackgroundTask, BackgroundTaskThread
from binaryninja.enums import SymbolType, SectionSemantics, VariableSourceType, SegmentFlag

from .log import logger
from .types import create_java_types
from .types import is_object_array
from .types.meta import SubstrateType
from .types.svm.info import ImageCodeInfo
from .heap import SvmHeap
from .define import recursively_define
from .callingconvention import SvmCallingConvention

def find_image_info(heap: SvmHeap):
    code_info_type = SubstrateType.by_name(heap, 'com.oracle.svm.core.code.ImageCodeInfo')
    search_offset = code_info_type['classes'].offset

    from .types.jdk.klass import SubstrateClass
    class_type = SubstrateClass.for_view(heap)
    for class_array in class_type.array_type.find_instances():
        if is_object_array(heap, class_array, class_type.is_instance) is None:
            continue

        for addr in heap.find_refs_to(class_array):
            if not code_info_type.is_instance(code_info := addr - search_offset):
                continue

            return code_info

def find_image_interned_strings(heap: SvmHeap):
    interned_strings_type = SubstrateType.by_name(heap, "com.oracle.svm.core.jdk.ImageInternedStrings")
    search_offset = interned_strings_type['imageInternedStrings'].offset

    from .types.jdk.string import SubstrateString
    string_type = SubstrateString.for_view(heap)
    for string_array in string_type.array_type.find_instances():
        if is_object_array(heap, string_array, string_type.is_instance) is None:
            continue

        for addr in heap.find_refs_to(string_array):
            if not interned_strings_type.is_instance(interned_strings := addr - search_offset):
                continue

            return interned_strings

def fixup_methods(heap: SvmHeap, image_code_info: ImageCodeInfo, *, task: BackgroundTask | None = None):
    named_methods = 0

    heap.view.set_analysis_hold(True)

    if task:
        task.progress = 'Defining vtable methods...'

    undefined_methods = set(image_code_info.method_table.keys())

    for method in (all_methods := set(
        func
        for klass in image_code_info.classes
        if klass is not None
        for func in klass.vtable
    )):
        heap.view.add_function(method, auto_discovered=True)

    heap.view.set_analysis_hold(False)

    heap.view.update_analysis_and_wait()

    vtable_methods = all_methods.copy()
    all_methods.update(
        func.start
        for func in heap.view.functions
        if image_code_info.code_start <= func.start < image_code_info.code_end
    )

    if task:
        task.progress = 'Fixing up known methods...'

    platform = heap.view.platform
    assert platform is not None

    ccs: dict[CallingConvention, SvmCallingConvention] = {}
    for calling_convention in platform.calling_conventions:
        cc = SvmCallingConvention(calling_convention)
        platform.register_calling_convention(cc)
        ccs[calling_convention] = cc

    heap.view.set_analysis_hold(True)
    for i, addr in enumerate(all_methods):
        if task:
            task.progress = f'Fixing up known methods ({i}/{len(all_methods)})...'
        else:
            print(f'Fixing up known methods ({i}/{len(all_methods)})...')

        func = heap.view.get_function_at(addr)
        if not func:
            continue

        if func.calling_convention:
            if func.calling_convention not in ccs:
                cc = SvmCallingConvention(func.calling_convention)
                platform.register_calling_convention(cc)
                ccs[func.calling_convention] = cc

            calling_convention = ccs.get(func.calling_convention, None)
        else:
            calling_convention = None

        try:
            method = image_code_info.lookup_method(addr)
        except:
            method = None

        if method is None:
            continue

        parameters = None

        if method:
            func.name = str(method)
            named_methods += 1
            if method.id in undefined_methods:
                undefined_methods.remove(method.id)

            # TODO: construct parameters here

        return_type = func.type.return_value
        if parameters is None:
            parameters = []
            for i, p in enumerate(func.type.parameters):
                if calling_convention:
                    if p.location and p.location.source_type == VariableSourceType.RegisterVariableSourceType:
                        if p.location.storage in [
                            calling_convention.heap_base_register,
                            calling_convention.thread_register,
                        ]:
                            continue

                if i == 0 and func.start in vtable_methods:
                    p = FunctionParameter(
                        method.klass.instance_type.registered_name,
                        'this',
                    )

                parameters.append(p)

        func.type = FunctionType.create(
            ret=return_type,
            params=parameters,
            calling_convention=calling_convention,
            variable_arguments=func.type.has_variable_arguments,
            stack_adjust=func.type.stack_adjustment,
            can_return=func.type.can_return,
            pure=func.type.pure,
        )


    if task:
        task.progress = f'Analysing methods...'

    heap.view.set_analysis_hold(False)

    logger.log_info(f"Finished retyping methods")

    heap.view.update_analysis()

    logger.log_info(f"Named {named_methods} methods")
    logger.log_info(f"Missed methodIds: {undefined_methods}")

    heap.view.update_analysis()

def _analyse(view: BinaryView, *, task: BackgroundTask | None = None):
    assert view.arch is not None

    create_java_types(view)

    heap = SvmHeap.for_view(view)

    # This won't be visible in Linear view
    if heap.base:
        view.define_data_var(
            heap.base,
            Type.void(),
            Symbol(
                SymbolType.ExternalSymbol,
                heap.base,
                '__svm_heap_base',
            ),
        )

    svm_internals_start = view.end
    view.add_user_segment(svm_internals_start, 0x10, 0, 0, SegmentFlag(0))
    view.add_user_section(
        '.svm_synthetics',
        svm_internals_start,
        0x10,
        SectionSemantics.ExternalSectionSemantics,
        entry_size=0,
    )
    view.define_data_var(
        svm_internals_start,
        Type.pointer(view.arch, Type.void()),
        Symbol(SymbolType.ExternalSymbol, svm_internals_start, '__svm_isolate_thread')
    )

    from .types.jdk.klass import SubstrateClass
    class_type = SubstrateClass.for_view(heap)
    class_type.hub_address = heap.class_hub

    start_addrs = []

    hub_support_type = SubstrateType.by_name(heap, 'com.oracle.svm.core.hub.DynamicHubSupport', find_hub=True)
    search_offset = hub_support_type['referenceMapEncoding'].offset

    if task:
        task.progress = 'Finding instance reference maps...'

    from .types.jdk.bytearray import SubstrateByteArray
    array_type = SubstrateByteArray.for_view(view)
    for hub_support in hub_support_type.find_instances():
        if (reference_map_obj := heap.read_pointer(hub_support + search_offset)) is None:
            continue

        if not array_type.is_instance(reference_map_obj):
            continue

        heap.instance_reference_map_len = view.read_int(reference_map_obj + array_type['len'].offset, 4)
        heap.instance_reference_map_offset = reference_map_obj + array_type['data'].offset
        logger.log_info(f"DynamicHubSupport: {hex(hub_support)}")
        start_addrs.append(hub_support)
        break

    # HACK: don't know how to cleanly separate from heap
    class_type.reconstruct_type(class_type.hub_address)

    if task:
        task.progress = 'Finding ImageCodeInfo(s)...'
    if (code_info_addr := find_image_info(heap)) is not None:
        logger.log_info(f"ImageCodeInfo: {hex(code_info_addr)}")
        start_addrs.append(code_info_addr)

    if task:
        task.progress = 'Finding heap strings...'
    if (interned_strings := find_image_interned_strings(heap)) is not None:
        logger.log_info(f"ImageInternedStrings: {hex(interned_strings)}")
        start_addrs.append(interned_strings)

    recursively_define(heap, start_addrs, task=task)

    if code_info_addr is not None:
        if task:
            task.progress = 'Parsing ImageCodeInfo...'

        image_code_info = ImageCodeInfo.for_view(heap)(code_info_addr)
        fixup_methods(heap, image_code_info, task=task)

class AnalysisTask(BackgroundTaskThread):
    def __init__(self, view: BinaryView):
        BackgroundTaskThread.__init__(self, 'Analysing SubstrateVM heap...', True)
        self.view = view

    def run(self):
        _analyse(self.view, task=self)
        self.finish()

def analyse(view: BinaryView):
    AnalysisTask(view).start()

PluginCommand.register('LyticEnzyme\\Analyse', '', analyse)

from .util import SvmHeapRenderer, SvmStringRecognizer
SvmHeapRenderer().register_type_specific()
SvmStringRecognizer().register()

# fields can just be... not included if it tree shaking analysis determines that it's not needed 