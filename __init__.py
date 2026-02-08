from binaryninja import BinaryView
from binaryninja.plugin import PluginCommand, BackgroundTaskThread

from .log import logger
from .types import create_java_types
from .types import is_object_array
from .types.meta import SubstrateType
from .types.svm.info import ImageCodeInfo
from .heap import SvmHeap
from .define import recursively_define

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

def _analyse(view: BinaryView, *, task: 'AnalysisTask' | None = None):
    create_java_types(view)

    heap = SvmHeap.for_view(view)

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
        image_code_info = ImageCodeInfo.for_view(heap)(code_info_addr)
        for method in (all_methods := set(
            func
            for klass in image_code_info.classes
            if klass is not None
            for func in klass.vtable
        )):
            view.add_function(method, auto_discovered=True)

        view.update_analysis_and_wait()

        for addr in all_methods:
            func = view.get_function_at(addr)
            try:
                method = image_code_info.lookup_method(addr)
            except:
                continue

            if method is None:
                continue

            func.name = str(method)

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