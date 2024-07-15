"""Tools for checking functions and exporting decompiled program to a .c file"""

# pylint: disable=wrong-import-order, wrong-import-position, import-error

from collections import OrderedDict
import pyhidra

pyhidra.start()
from ghidra.program.model.data import DataTypeWriter

TYPES_TO_REPLACE = OrderedDict(byte="unsigned char",
                               dwfenc="unsigned char",
                               dword="unsigned int",
                               qword="unsigned long",
                               word="unsigned short",
                               uint="unsigned int",
                               undefined1="uint8_t",
                               undefined2="uint16_t",
                               undefined4="uint32_t",
                               undefined8="uint64_t",
                               undefined="unsigned int"
                               )


def function_in_runtime(function):
    """Check if input function is from C Runtime"""
    function_name = function.getName()
    return function_name.startswith('_')


def address_to_int(address):
    """Address is a number in hex"""
    return int(str(address), 16)


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


def write_program_data_types(program, c_file_writer, monitor, library_list):
    """Dumping program data types"""
    dtm = program.getDataTypeManager()
    data_type_writer = DataTypeWriter(dtm, c_file_writer,)
    for data_type in dtm.getAllDataTypes():
        if data_type.getPathName().split('/')[1] in library_list:
            dtm.remove(data_type, monitor)
    data_type_writer.write(dtm, monitor)


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
