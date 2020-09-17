from mach_o_execute import *
from prepare_function import *

BASE = 0x10000000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024

binary_path = '/Users/Zyciac/Desktop/ipas/on_device_positive/com.schedule.BarieTeacher/Payload/ChalkTeacher.app/ChalkTeacher'
function_start = 0x31BDB8
function_end = 0x31BEF0

code = read_code_from_binary(binary_path, function_start, function_end)
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
disasm_macho(cs, code, function_start, function_end)

runtime_ref = get_runtime_ref(binary_path, function_start, function_end)
for i in range(len(runtime_ref.msgsend_list)):
    runtime_ref.msgsend_list[i]+=BASE
for i in range(len(runtime_ref.ignore_list)):
    runtime_ref.ignore_list[i] += BASE
# for i in runtime_ref.msgsend_list:
#     print(hex(i))

def hook_code(mu, address, size, user_data = runtime_ref):
    print(hex(mu.reg_read(UC_ARM64_REG_X20)))
    if address in runtime_ref.msgsend_list:
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        x1 = mu.reg_read(UC_ARM64_REG_X1)
        print('at address {}, x0 is {}'.format(hex(address), hex(x0)))
        print('x1 is {}'.format(hex(x1)))
        mu.reg_write(UC_ARM64_REG_PC, address+size)
    elif address in runtime_ref.ignore_list:
        mu.reg_write(UC_ARM64_REG_PC, address+size)

macho_execute(binary_path, function_start, function_end, hook_code)

## code = self._mu.mem_read(addr, size)