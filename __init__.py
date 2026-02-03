from binaryninja import BinaryView
from binaryninja.plugin import PluginCommand, BackgroundTaskThread

from .log import logger
from .types import create_java_types
from .types import is_instance_of_type, find_instances_by_type_name
from .types import is_object_array
from .heap import SvmHeap
from .define import recursively_define

def find_image_info(heap: SvmHeap):
    if (code_info_type := heap.view.get_type_by_name("com.oracle.svm.core.code.ImageCodeInfo")):
        search_offset = code_info_type['classes'].offset
    else:
        search_offset = 0x60

    from .types.jdk.klass import SubstrateClass
    class_type = SubstrateClass.for_view(heap.view)
    for class_array in find_instances_by_type_name(heap, "[Ljava.lang.Class;"):
        if is_object_array(heap, class_array, lambda n, e: class_type.is_instance(e)) is None:
            continue

        for addr in heap.find_refs_to(class_array):
            if not is_instance_of_type(heap, code_info := addr - search_offset, "com.oracle.svm.core.code.ImageCodeInfo"):
                continue

            return code_info

def find_image_interned_strings(heap: SvmHeap):
    if (interned_strings_type := heap.view.get_type_by_name("com.oracle.svm.core.jdk.ImageInternedStrings")):
        search_offset = interned_strings_type['imageInternedStrings'].offset
    else:
        search_offset = 0x8

    from .types.jdk.string import is_string_instance
    for string_array in find_instances_by_type_name(heap, "[Ljava.lang.String;"):
        if is_object_array(heap, string_array, is_string_instance) is None:
            continue

        for addr in heap.find_refs_to(string_array):
            if not is_instance_of_type(heap, interned_strings := addr - search_offset, "com.oracle.svm.core.jdk.ImageInternedStrings"):
                continue

            return interned_strings

def _analyse(view: BinaryView, *, task: 'AnalysisTask' | None = None):
    create_java_types(view)

    heap = SvmHeap.for_view(view)

    start_addrs = []

    if (hub_support_type := heap.view.get_type_by_name("com.oracle.svm.core.hub.DynamicHubSupport")):
        search_offset = hub_support_type['referenceMapEncoding'].offset
    else:
        search_offset = 0x8

    if task:
        task.progress = 'Finding instance reference maps...'

    for hub_support in find_instances_by_type_name(heap, "com.oracle.svm.core.hub.DynamicHubSupport"):
        if (reference_map_obj := heap.read_pointer(hub_support + search_offset)) is None:
            continue

        from .types.jdk.bytearray import is_byte_array
        if not is_byte_array(heap, reference_map_obj):
            continue

        heap.instance_reference_map_offset = reference_map_obj + heap.view.get_type_by_name('byte[]')['data'].offset
        logger.log_info(f"DynamicHubSupport: {hex(hub_support)}")
        start_addrs.append(hub_support)
        break

    if task:
        task.progress = 'Finding ImageCodeInfo(s)...'
    if (code_info := find_image_info(heap)) is not None:
        logger.log_info(f"ImageCodeInfo: {hex(code_info)}")
        start_addrs.append(code_info)

    if task:
        task.progress = 'Finding heap strings...'
    if (interned_strings := find_image_interned_strings(heap)) is not None:
        logger.log_info(f"ImageInternedStrings: {hex(interned_strings)}")
        start_addrs.append(interned_strings)

    recursively_define(heap, start_addrs, task=task)

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
