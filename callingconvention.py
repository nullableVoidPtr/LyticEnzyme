from binaryninja.callingconvention import CallingConvention
from binaryninja.architecture import RegisterName, RegisterIndex, RegisterType
from binaryninja.function import Function
from binaryninja.variable import ConstantPointerRegisterValue, ExternalPointerRegisterValue, ImportedAddressRegisterValue

from .heap import SvmHeap

class SvmCallingConvention(CallingConvention):
	base: CallingConvention

	code_base_register: RegisterIndex | None
	heap_base_register: RegisterIndex
	thread_register: RegisterIndex

	def __init__(self, base: CallingConvention, *args, **kwargs):
		self.base = base
		code_base_register: RegisterName = None

		match self.base.arch.name:
			case 'x86_64':
				code_base_register = 'r13'
				heap_base_register = 'r14'
				thread_register = 'r15'
			case 'aarch64':
				code_base_register = 'r26'
				heap_base_register = 'r27'
				thread_register = 'r28'
			case 'rv64gc':
				heap_base_register = 'x27'
				thread_register = 'x23'
			case _:
				raise ValueError('Unsupported architecture')

		self.arg_regs_for_varargs = self.base.arg_regs_for_varargs
		self.arg_regs_share_index = self.base.arg_regs_share_index
		self.callee_saved_regs = self.base.callee_saved_regs.copy()
		self.caller_saved_regs = self.base.caller_saved_regs.copy()
		self.eligible_for_heuristics = self.base.eligible_for_heuristics
		self.float_arg_regs = self.base.float_arg_regs.copy()
		self.float_return_reg = self.base.float_return_reg
		self.global_pointer_reg = self.base.global_pointer_reg
		self.high_int_return_reg = self.base.high_int_return_reg
		self.implicitly_defined_regs = self.base.implicitly_defined_regs.copy()
		self.int_arg_regs = self.base.int_arg_regs.copy()
		self.int_return_reg = self.base.int_return_reg
		self.stack_adjusted_on_return = self.base.stack_adjusted_on_return
		self.stack_reserved_for_arg_regs = self.base.stack_reserved_for_arg_regs

		if code_base_register and False:
			self.code_base_register = self.base.arch.get_reg_index(code_base_register)
		else:
			self.code_base_register = None

		self.heap_base_register = self.base.arch.get_reg_index(heap_base_register)
		self.thread_register = self.base.arch.get_reg_index(thread_register)

		for reg in [self.code_base_register, self.heap_base_register, self.thread_register]:
			if reg is None:
				continue

			if reg not in self.implicitly_defined_regs:
				self.implicitly_defined_regs.append(reg)

			for reg_list in [
				self.int_arg_regs,
				self.callee_saved_regs,
				self.caller_saved_regs,
			]:
				if reg in reg_list:
					reg_list.remove(reg)

		super().__init__(self.base.arch, name=self.base.name+'-svm', *args, **kwargs)

	def perform_get_incoming_reg_value(self, reg: RegisterName, func: Function):
		try:
			reg_num = self.arch.get_reg_index(reg)
		except:
			return self.base.perform_get_incoming_reg_value(reg, func)

		match reg_num:
			case self.code_base_register:
				# raise NotImplementedError
				pass
			case self.heap_base_register:
				if (heap := SvmHeap.for_view(func.view)).base is not None:
					return ConstantPointerRegisterValue(heap.base)
			case self.thread_register:
				return ImportedAddressRegisterValue(func.view.get_symbols_by_name('__svm_isolate_thread')[0].address)

		return self.base.perform_get_incoming_reg_value(reg, func)