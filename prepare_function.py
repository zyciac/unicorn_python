'''
    given a function, pre-process to 
    1. filter out unnecessary instructions
    2. highlight jump instructions 
        a. further classify into 1)runtime function, 2)dylib function
'''

from capstone import *
from macho_files.utilities.parse_macho import my_parser

import struct

SEMANTIC_TYPE_FUNCTION = 999
SEMANTIC_TYPE_STRING = 888
SEMANTIC_TYPE_INTEGER = 777

class Semantic:
    def __init__(self, type, value):
        self.type = type
        self.value = {}
        self.value[self.type] = value

    
    def get_value(self):
        return self.value[self.type]

    def update_value(self, value):
        if self.type == 0:
            raise(RuntimeError('Initialize semantic type first'))
        self.value[self.type] = value
    

class Runtime_Ref:
    def __init__(self):
        self.msgsend_list = []
        self.ignore_list = []

def read_code_from_binary(binary_path, start, end):
    size = end - start
    f = open(binary_path, 'rb')
    f.seek(start)
    code = f.read(size)
    f.close()
    return code

def disasm_macho(cs, code, start, end):
    #print(hex(start))
    for i in cs.disasm(code, 0x0):
        print("0x%x:\t%s\t%s" %(i.address+start, i.mnemonic, i.op_str))


def return_function_jump_addr(cs, code, start, end):
    '''
        return a list of jump instruction address
    '''
    #print('start in return_function_jump_addr is {}'.format(hex(start)))
    jump_instruction = {}
    jump_instruction['bl'] = []
    jump_instruction['b'] = []
    jump_instruction['blr'] = []
    cursor = 0
    try:
        for i in cs.disasm(code, 0x0):
            if i.mnemonic == 'bl':
                #print(int(i.op_str[1:], 16))
                jump_to_addr = int(i.op_str[1:], 16) + start
                addr = start + cursor
                jump_instruction['bl'].append((addr, jump_to_addr))
            elif i.mnemonic == 'b':
                jump_to_addr = int(i.op_str[1:], 16) + start
                addr = start + cursor
                jump_instruction['b'].append((addr, jump_to_addr))
            elif i.mnemonic == 'blr':
                jump_to_addr = int(i.op_str[1:], 16) + start
                addr = start + cursor
                jump_instruction['blr'].append((addr, jump_to_addr))
            else:
                pass
            cursor += 4
    except Exception as e:
        print(e)
        print("0x%x:\t%s\t%s" %(i.address+start, i.mnemonic, i.op_str))
    return jump_instruction


def addr_in_text_segment(text_segment, address):
    return (text_segment.offset + text_segment.size) - address > 0


def addr_in_data_segment(data_segment, address):
    return (data_segment.offset + data_segment.size) - address > 0


# redundant API! Too lazy to modify.
def return_section_in_text_segment(text_segment, address):
    for section in text_segment.text_section_list:
        if section.offset + section.size > address:
            return section


# redundant API! Too lazy to modify.
def return_section_in_data_segment(data_segment, address):
    for section in data_segment.data_section_list:
        if section.offset + section.size > address:
            return section

        
def which_section(macho_offset, address):
    '''
        input an absolute address in the binary file,
        output the section that it belongs to
    '''
    #print(hex(address))

    # DATA segment is adjacent to and behind TEXT segment
    if addr_in_text_segment(macho_offset.my_text_segment, address):
        return return_section_in_text_segment(macho_offset.my_text_segment, address)
    elif addr_in_data_segment(macho_offset.my_data_segment, address):
        return return_section_in_data_segment(macho_offset.my_data_segment, address)
    else:
        raise RuntimeError('EXCEPTION: The address is neither in DATA of in TEXT!')


def get_stub_function_address(cs, code, operand_address):
    instruction = list(cs.disasm(code, 0x0))[1]
    #print(instruction.op_str)
    relative_addr = instruction.op_str.split(' ')[1][1:]
    # print(type(relative_addr))
    relative_addr = int(relative_addr, 16)
    addr = relative_addr+operand_address
    #print(hex(addr))
    return addr

# def read_code_from_macho(binary_path, offset, size):
#     f = open(binary_path, 'rb')
#     f.seek(offset)
#     code = f.read(size)
#     f.close()
#     return code


def parse_lazy_binding_opcode(lazy_binding_opcodes):
    '''
        parse lazy_binding_info part in Dynamic_loader_info, return the function name
    '''
    BIND_OPCODE_DONE                            = 0x00
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM           = 0x10
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB          = 0x20
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM           = 0x30
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM   = 0x40
    BIND_OPCODE_SET_TYPE_IMM                    = 0x50
    BIND_OPCODE_SET_ADDEND_SLEB                 = 0x60
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB	    = 0x70
    BIND_OPCODE_ADD_ADDR_ULEB                   = 0x80
    BIND_OPCODE_DO_BIND	                        = 0x90
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB           = 0xA0
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED     = 0xB0
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0
    mask_high = 0xf0
    mask_low = 0xf
    function_name = ''
    length = len(lazy_binding_opcodes)
    if (lazy_binding_opcodes[2] & mask_high) == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        function_name = read_string(lazy_binding_opcodes[5:])
    elif (lazy_binding_opcodes[2] & mask_high) == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        function_name = read_string(lazy_binding_opcodes[4:])
    else:
        raise(RuntimeError('EXCEPTION: parsing lazy binding opcode failed'))
    # if function_name == '_objc_msgSend':
    #     print(function_name)
    return function_name


def read_string(bytes):
    index = bytes.find(0)
    string_bytes = bytes[0:index]
    string = ''
    for char in string_bytes:
        string+=chr(char)
    #print(string)
    return string

    
def handle_address_in_stub_semantic(cs, binary_path, operand_address, macho_offset):
    '''
        bl #addr_A,
        addr_A in la_symbol_ptr,
        pinter at addr_A value refers to code in stub
        code in stub refers to an offset in the lazy_Binding_Info, start+offset
        parse opcode in the referred offset till BIND_OPCODE_DONE we can have the name of the method.
    '''
    
    semantic = Semantic(SEMANTIC_TYPE_FUNCTION, '')
    f = open(binary_path, 'rb')
    f.seek(operand_address)
    code = f.read(12)
    
    #disasm_macho(cs, code, operand_address, address+12)
    #print()
    address_code = code[4:8]
    address_code = address_code[::-1]
    la_ptr_addr = get_stub_function_address(cs, code, operand_address)
    f.seek(la_ptr_addr)
    stub_helper_address = struct.unpack("<Q", f.read(8))[0]
    stub_helper_address -= 0x100000000
    #print(hex(stub_helper_address))

    f.seek(stub_helper_address+8)
    lazy_offset = struct.unpack('<I', f.read(4))[0]
    #print(hex(lazy_offset))

    lazy_binding_info_offset = macho_offset.lazy_binding_info_offset+lazy_offset
    #print(hex(lazy_binding_info_offset))
    lazy_binding_opcodes = read_code_from_binary(binary_path, lazy_binding_info_offset, lazy_binding_info_offset+50) # assume the string name is short
    semantic.update_value(parse_lazy_binding_opcode(lazy_binding_opcodes))

    f.close()
    return semantic

    # for byte in address_code:
    #     print(hex(int(byte)), end=' ')
    # print()
    
def handle_semantic_address(cs, binary_path, macho_offset, operand_address):
    section = which_section(macho_offset, operand_address)
    if section.section_name == '__stubs':
        semantic = handle_address_in_stub_semantic(cs, binary_path, operand_address, macho_offset)
    else:
        print('has not considered address in this section: {}'.format(section.section_name))
    return semantic


def get_runtime_ref(binary_path, function_start, function_end):
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    code = read_code_from_binary(binary_path, function_start, function_end)
    my_macho_offset = my_parser(binary_path)
    jump_instruction = return_function_jump_addr(cs, code, start, end)

    my_runtime_ref = Runtime_Ref()

    for address, jump_to_addr in jump_instruction['bl']:
        #print('at the address: {} is a jump instruction'.format(hex(address)))
        #print('jump to {}'.format(hex(jump_to_addr)))
        #print()
        semantic = handle_semantic_address(cs, binary_path, my_macho_offset, jump_to_addr)
        print('at address: {}, is a {}'.format(hex(address), semantic.get_value()))
        if semantic.get_value() == '_objc_msgSend':
            my_runtime_ref.msgsend_list.append(address)
        else:
            my_runtime_ref.ignore_list.append(address)

    return my_runtime_ref


if __name__ ==   '__main__':
    binary_path = '/Users/Zyciac/Desktop/ipas/on_device_positive/com.schedule.BarieTeacher/Payload/ChalkTeacher.app/ChalkTeacher'
    #binary_path = '/Users/Zyciac/Desktop/Solitaire'
    start = 0x31BDB8
    end = 0x31BEF4
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    code = read_code_from_binary(binary_path, start, end)
    my_macho_offset = my_parser(binary_path)
    #print(hex(my_macho_offset.my_data_segment.offset))
    print('---disassembling the function---')
    disasm_macho(cs, code, start, end)

    # print('\n---printing out jump instruction address---')
    jump_instruction = return_function_jump_addr(cs, code, start, end)
    # for address in jump_instruction['bl']:
    #     section = which_section(my_macho_offset, address)
    #     print(section.section_name)
    # address = 0x3edc10
    print('---The followings are jump instructions---')

    my_runtime_ref = Runtime_Ref()
    my_runtime_ref.msgsend_list = []
    my_runtime_ref.ignore_list = []
    for address, jump_to_addr in jump_instruction['bl']:
        #print('at the address: {} is a jump instruction'.format(hex(address)))
        #print('jump to {}'.format(hex(jump_to_addr)))
        #print()
        semantic = handle_semantic_address(cs, binary_path, my_macho_offset, jump_to_addr)
        print('at address: {}, is a {}'.format(hex(address), semantic.get_value()))
        if semantic.get_value() == '_objc_msgSend':
            my_runtime_ref.msgsend_list.append(address)
        else:
            my_runtime_ref.ignore_list.append(address)
    
    for addr in my_runtime_ref.msgsend_list:
        print(hex(addr))
    
   
    get_runtime_ref(binary_path, start, end)