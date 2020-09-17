from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *

from capstone import *
from capstone.arm64 import *

import struct

def hook_code(mu, address, size, user_data):
    #print(mu.reg_read(UC_ARM64_REG_X1))
    pass


def macho_execute(binary, start, end, hook_function):
    f = open(binary, 'rb')
    ARM64_CODE = f.read()

    BASE = 0x100000000
    STACK_ADDR = 0x0
    STACK_SIZE = 1024*1024

    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu.mem_map(BASE, 0xf000000)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    mu.mem_write(BASE, ARM64_CODE)
    mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE - 1)

    start = BASE+start
    end = BASE + end
    mu.hook_add(UC_HOOK_CODE, hook_function)
    mu.emu_start(start, end)

    # x0 = mu.reg_read(UC_ARM64_REG_X0)
    # x1 = mu.reg_read(UC_ARM64_REG_X1)
    # x2 = mu.reg_read(UC_ARM64_REG_X2)
    # x8 = mu.reg_read(UC_ARM64_REG_X8)
    # x9 = mu.reg_read(UC_ARM64_REG_X9)
    # sp = mu.reg_read(UC_ARM64_REG_SP)
    # print('sp is {}'.format(hex(sp)))
    # print('x0 is {}'.format(hex(x0)))
    # print('x1 is {}'.format(hex(x1)))
    # print('x2 is {}'.format(hex(x2)))
    # print('x8 is {}'.format(hex(x8)))
    # print('x9 is {}'.format(hex(x9)))

    # print('stack value')
    # size = 0x60
    # print(type(size))
    # stack_value_list = read_stack(mu, sp, size)
    # show_stack_value(stack_value_list)


def read_stack(mu, sp, size):
    '''
        stack value depends on the BASE of emulation
    '''
    stack_value = mu.mem_read(sp, size)
    value_list = []
    for i in range(int(size/8)):
        value_64bit_bytes = stack_value[i*8:i*8+4]
        value_64bit = struct.unpack('<I', value_64bit_bytes)[0]
        value_list.append(value_64bit)
    return value_list


def show_stack_value(stack_value_list):
    for i in stack_value_list:
        print(hex(i))



if __name__ == '__main__':
    binary = '/Users/Zyciac/Desktop/ipas/on_device_positive/com.schedule.BarieTeacher/Payload/ChalkTeacher.app/ChalkTeacher'
    start = 0x31BDB8
    end = 0x31BE30
    # binary = '/Users/Zyciac/Desktop/Solitaire'
    # start = 0x87488c
    # end = 0x874894
    # disasm_macho(binary, start, end)
    #print('****** register values ******')
    macho_execute(binary, start, end, hook_code)
    # return_function_jump_addr(binary, start, end)
