from binaryninja.callingconvention import CallingConvention
from binaryninja.architecture import RegisterName, RegisterIndex
from binaryninja.function import Function
from binaryninja.variable import Undetermined, ConstantPointerRegisterValue, ImportedAddressRegisterValue
from binaryninja.callingconvention import core 
from binaryninja.log import log_error_for_exception

import ctypes

from .heap import SvmHeap

class SvmCallingConvention(CallingConvention):
	base: CallingConvention

	code_base_register: RegisterName | None
	heap_base_register: RegisterName
	thread_register: RegisterName

	def __init__(self, base: CallingConvention, *args, **kwargs):
		self.base = base

		self.code_base_register = None
		match self.base.arch.name:
			case 'x86_64':
				if False:
					self.code_base_register = 'r13'
				self.heap_base_register = 'r14'
				self.thread_register = 'r15'
			case 'aarch64':
				if False:
					self.code_base_register = 'r26'
				self.heap_base_register = 'r27'
				self.thread_register = 'r28'
			case 'rv64gc':
				self.heap_base_register = 'x27'
				self.thread_register = 'x23'
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

	# TODO: figure out metaclass to avoid this mess
	# For some reason, the CC api defers to self.__class__, not self.__dict__....
	def _get_caller_saved_regs(self, ctxt, count):
		try:
			regs = self.caller_saved_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_caller_saved_regs")
			count[0] = 0
			return None

	def _get_callee_saved_regs(self, ctxt, count):
		try:
			regs = self.callee_saved_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_callee_saved_regs")
			count[0] = 0
			return None

	def _get_int_arg_regs(self, ctxt, count):
		try:
			regs = self.int_arg_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_int_arg_regs")
			count[0] = 0
			return None

	def _get_float_arg_regs(self, ctxt, count):
		try:
			regs = self.float_arg_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_float_arg_regs")
			count[0] = 0
			return None

	def _arg_regs_share_index(self, ctxt):
		return self.arg_regs_share_index

	def _arg_regs_used_for_varargs(self, ctxt):
		return self.arg_regs_for_varargs

	def _stack_reserved_for_arg_regs(self, ctxt):
		return self.stack_reserved_for_arg_regs

	def _stack_adjusted_on_return(self, ctxt):
		return self.stack_adjusted_on_return

	def _eligible_for_heuristics(self, ctxt):
		return self.eligible_for_heuristics

	def _get_int_return_reg(self, ctxt):
		if self.int_return_reg is None:
			return False

		return self.arch.regs[self.int_return_reg].index

	def _get_high_int_return_reg(self, ctxt):
		if self.high_int_return_reg is None:
			return 0xffffffff
		
		return self.arch.regs[self.high_int_return_reg].index

	def _get_float_return_reg(self, ctxt):
		if self.float_return_reg is None:
			return 0xffffffff
		
		return self.arch.regs[self.float_return_reg].index

	def _get_global_pointer_reg(self, ctxt):
		if self.global_pointer_reg is None:
			return 0xffffffff

		return self.arch.regs[self.global_pointer_reg].index

	def _get_implicitly_defined_regs(self, ctxt, count):
		try:
			regs = self.implicitly_defined_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_implicitly_defined_regs")
			count[0] = 0
			return None

	def perform_get_incoming_reg_value(self, reg: RegisterName, func: Function):
		match reg:
			# case self.code_base_register:
				# raise NotImplementedError
			case self.heap_base_register:
				if (heap := SvmHeap.for_view(func.view)).base is not None:
					return ConstantPointerRegisterValue(heap.base)
			case self.thread_register:
				return ImportedAddressRegisterValue(func.view.get_symbols_by_name('__svm_isolate_thread')[0].address)
			case _:
				return self.base.get_incoming_reg_value(reg, func)
		
		return Undetermined()

	def _get_incoming_flag_value(self, ctxt, flag, func, result):
		try:
			func_obj = Function(handle=core.BNNewFunctionReference(func))
			flag_name = self.arch.get_flag_name(flag)
			api_obj = self.base.get_incoming_flag_value(flag_name, func_obj)._to_core_struct()
		except:
			log_error_for_exception("Unhandled Python exception in CallingConvention._get_incoming_flag_value")
			api_obj = Undetermined()._to_core_struct()
		result[0].state = api_obj.state
		result[0].value = api_obj.value

	def perform_get_incoming_var_for_parameter_var(self, *args):
		return self.base.get_incoming_var_for_parameter_var(*args)

	def perform_get_parameter_var_for_incoming_var(self, *args):
		return self.base.get_parameter_var_for_incoming_var(*args)