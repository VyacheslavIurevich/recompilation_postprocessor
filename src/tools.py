"""Tools for checking functions and exporting decompiled program to a .c file"""

# pylint: disable=wrong-import-order, wrong-import-position, import-error

from collections import OrderedDict
from math import floor, log2
import pyhidra

pyhidra.start()
from ghidra.program.model.data import DataTypeWriter

TYPES_TO_REPLACE = OrderedDict(uint="unsigned int",
                               ushort="unsigned short",
                               ulong="unsigned long")
CONCAT_LEN = 6  # = len("CONCAT")
BYTE_SIZE = 8
HEX_BASE = 16
RUNTIME_PREFIX = '_'
PLT_INSTRUCTION = "JMP qword ptr"
STACK_PROTECTOR_VARIABLE = "in_FS_OFFSET"


def address_to_int(address):
    """Address is a number in hex"""
    return int(str(address), HEX_BASE)


def function_in_runtime(function):
    """Check if input function is from C Runtime"""
    function_name = function.getName()
    return function_name.startswith(RUNTIME_PREFIX)


def function_is_plt(function):
    """Check if input function is PLT jump"""
    program = function.getProgram()
    listing = program.getListing()
    body = function.getBody()
    min_address = address_to_int(body.getMinAddress())
    max_address = address_to_int(body.getMaxAddress())
    for address in body.getAddresses(True):
        code_unit = str(listing.getCodeUnitAt(address))
        if code_unit.startswith(PLT_INSTRUCTION):
            words = code_unit.split()
            jmp_address = address_to_int(words[-1][1:-1])  # [1:-1] is to remove [] from address
            if not min_address <= jmp_address <= max_address:
                return True
    return False


def exclude_function(function):
    """Dumping program data types"""
    entry_point = function.getEntryPoint()
    code_unit_at = function.getProgram().getListing().getCodeUnitAt(entry_point)
    return function_in_runtime(function) \
        or function_is_plt(function) \
        or code_unit_at.getMnemonicString() == "??"


def write_program_data_types(program, file_writer, monitor):
    """Dumping program data types"""
    dtm = program.getDataTypeManager()
    data_type_writer = DataTypeWriter(dtm, file_writer)
    data_type_list = []
    for data_type in dtm.getAllDataTypes():
        if ".h" not in data_type.getPathName().split('/')[1]:
            data_type_list.append(data_type)
    data_type_writer.write(data_type_list, monitor)
    dtm.close()


def replace_types(code):
    """Replacing all Ghidra types with types from intttypes.h and standart C types"""
    for old_type, new_type in TYPES_TO_REPLACE.items():
        code = code.replace(old_type, new_type)
    return code


def remove_stack_protection(code):
    """Removal of stack protection from code"""
    lines = code.split('\n')
    for num, line in enumerate(lines):
        if STACK_PROTECTOR_VARIABLE in line:
            # if we have "if ..." with in_FS_OFFSET checking
            # we must remove all "if" block - 4 lines (with ghidra comment)
            if "if" in line:
                # if == is in the condition:
                # lines[num] = "if ... == ... STACK_PROTECTOR_VARIABLE {"
                # lines[num + 1] = "  return 0;"
                # lines[num + 2] = "}"
                # lines[num + 3] is Ghidra's comment
                # lines[num + 4] = "__stack_chk_fail();"
                # if != is in the condition:
                # lines[num] = "if ... != ... STACK_PROTECTOR_VARIABLE {"
                # lines[num + 1] is Ghidra's comment
                # lines[num + 2] = "__stack_chk_fail();"
                # lines[num + 3] = "}"
                # lines[num + 4] = "return 0;" - we keep it
                if "==" in line:
                    lines[num + 1] = lines[num + 1][2:]
                    lines.pop(num + 4)
                lines.pop(num + 3)
                lines.pop(num + 2)
                if "!=" in line:
                    lines.pop(num + 1)
            lines.pop(num)
    new_code = '\n'.join(lines)
    return new_code


def handle_function(code):
    """Handling function code"""
    code_replaced_types = replace_types(code)
    if STACK_PROTECTOR_VARIABLE not in code_replaced_types:
        return code_replaced_types
    code_removed_stack_protection = remove_stack_protection(code_replaced_types)
    return code_removed_stack_protection


def get_nearest_lower_power_2(num):
    """Rounds a number to nearest lower power of 2"""
    return 2 ** floor(log2(num))


def put_concat(file_writer, code, used_concats):
    """Puts CONCATXY functions into C code"""
    concat_cnt = code.count("CONCAT")
    concat_idx = 0
    for _ in range(concat_cnt):
        concat_idx = code.find("CONCAT", concat_idx) + CONCAT_LEN
        first_size = int(code[concat_idx])
        second_size = int(code[concat_idx + 1])
        if (first_size, second_size) in used_concats:
            continue
        first_inttype_size = get_nearest_lower_power_2(first_size * BYTE_SIZE)
        second_inttype_size = get_nearest_lower_power_2(second_size * BYTE_SIZE)
        concat_name = f"unsigned long CONCAT{first_size}{second_size}"
        concat_args = f"(uint{first_inttype_size}_t a, uint{second_inttype_size}_t b)\n"
        concat_body = \
            f"return ((unsigned long)b) | (unsigned long)a << ({second_size} * {BYTE_SIZE});"
        concat_signature = concat_name + concat_args
        concat_function = concat_signature + '{' + '\n' + '\t' + concat_body + '\n' + '}' + '\n'
        file_writer.println(concat_function)
        used_concats.add((first_size, second_size))
    return used_concats


def line_from_body(line, signature):
    """Line is from function body if it is not a comment, is not empty, 
    is not a { or } and is not its signature"""
    return not (line.startswith(("//", "/*")) or line == ''
                or line in "{}" or line == signature[:-1])


def is_single_return(code, signature):
    """If function body consists of only one return;, it is service function"""
    body = [line for line in code.split('\n') if line_from_body(line, signature)]
    return len(body) == 1 and body[0].replace(' ', '') == "return;"
