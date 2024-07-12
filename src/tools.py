'''Tools for checking functions and exporting decompiled program to a .c file'''

#pylint: disable=wrong-import-order, wrong-import-position, import-error

import pyhidra
pyhidra.start()
from ghidra.program.model.data import DataTypeWriter

def function_in_runtime(function):
    '''Check if input function is from C Runtime'''
    function_name = function.getName()
    return function_name.startswith('_')

def address_to_int(address):
    '''Address is a number in hex'''
    return int(str(address), 16)

def function_is_plt(function):
    '''Check if input function is PLT jump'''
    program = function.getProgram()
    listing = program.getListing()
    body = function.getBody()
    min_address = address_to_int(body.getMinAddress())
    max_address = address_to_int(body.getMaxAddress())
    for address in body.getAddresses(True):
        code_unit = str(listing.getCodeUnitAt(address))
        if code_unit.startswith("JMP qword ptr"):
            words = code_unit.split()
            jmp_address = address_to_int(words[-1][1:-1]) # [1:-1] is to remove [] from address
            if not min_address <= jmp_address <= max_address:
                return True
    return False

def write_program_data_types(program, c_file_writer, monitor):
    """Dumping program data types"""
    dtm = program.getDataTypeManager()
    data_type_writer = DataTypeWriter(dtm, c_file_writer, False)
    data_type_writer.write(dtm, monitor)

def exclude_function(function):
    """Dumping program data types"""
    entry_point = function.getEntryPoint()
    code_unit_at = function.getProgram().getListing().getCodeUnitAt(entry_point)
    return \
        function_in_runtime(function) or \
        function_is_plt(function) or \
        code_unit_at.getMnemonicString() == "??"
