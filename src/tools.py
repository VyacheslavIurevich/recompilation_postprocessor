"""Tools for checking functions and exporting decompiled program to a .c file"""

# pylint: disable=wrong-import-order, wrong-import-position, import-error

from collections import OrderedDict
from math import floor, log2
import pyhidra

pyhidra.start()
from ghidra.program.model.data import DataTypeWriter

TYPES_TO_REPLACE = OrderedDict(uint="unsigned int")
CONCAT_LEN = 6  # = len("CONCAT")
BYTE_SIZE = 8
HEX_BASE = 16
RUNTIME_PREFIX = '_'


def function_in_runtime(function):
    """Check if input function is from C Runtime"""
    function_name = function.getName()
    return function_name.startswith(RUNTIME_PREFIX)


def address_to_int(address):
    """Address is a number in hex"""
    return int(str(address), HEX_BASE)


def function_is_plt(function):
    """Check if input function is PLT jump"""
    program = function.getProgram()
    listing = program.getListing()
    body = function.getBody()
    min_address = address_to_int(body.getMinAddress())
    max_address = address_to_int(body.getMaxAddress())
    for address in body.getAddresses(True):
        code_unit = str(listing.getCodeUnitAt(address))
        if code_unit.startswith("JMP qword ptr"):
            words = code_unit.split()
            jmp_address = address_to_int(words[-1][1:-1])  # [1:-1] is to remove [] from address
            if not min_address <= jmp_address <= max_address:
                return True
    return False


def write_program_data_types(program, c_file_writer, monitor):
    """Dumping program data types"""
    dtm = program.getDataTypeManager()
    data_type_writer = DataTypeWriter(dtm, c_file_writer)
    data_type_list = []
    for data_type in dtm.getAllDataTypes():
        if ".h" not in data_type.getPathName().split('/')[1]:
            data_type_list.append(data_type)
    data_type_writer.write(data_type_list, monitor)
    dtm.close()


def exclude_function(function):
    """Dumping program data types"""
    entry_point = function.getEntryPoint()
    code_unit_at = function.getProgram().getListing().getCodeUnitAt(entry_point)
    return function_in_runtime(function) \
        or function_is_plt(function) \
        or code_unit_at.getMnemonicString() == "??"


def replace_types(function_code):
    """Replacing all Ghidra types with types from intttypes.h and standart C types"""
    for old_type, new_type in TYPES_TO_REPLACE.items():
        function_code = function_code.replace(old_type, new_type)
    return function_code


def get_nearest_lower_power_2(num):
    """Rounds a number to nearest lower power of 2"""
    return 2 ** floor(log2(num))


def put_concat(file_writer, function_code, used_concats):
    """Puts CONCATXY functions into C code"""
    concat_cnt = function_code.count("CONCAT")
    concat_idx = 0
    for _ in range(concat_cnt):
        concat_idx = function_code.find("CONCAT", concat_idx) + CONCAT_LEN
        first_size = int(function_code[concat_idx])
        second_size = int(function_code[concat_idx + 1])
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
