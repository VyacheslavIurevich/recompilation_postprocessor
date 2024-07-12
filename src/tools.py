'''Tools for checking functions and exporting decompiled program to a .c file'''

#pylint: disable=wrong-import-order, wrong-import-position, import-error
import pyhidra
pyhidra.start()
from ghidra.program.model.data import DataTypeWriter
from java.io import PrintWriter

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

def write_program_data_types(program, file, monitor):
    """Dumping program data types"""
    dtm = program.getDataTypeManager()
    c_file_writer = PrintWriter(file)
    data_type_writer = DataTypeWriter(dtm, c_file_writer, False)
    data_type_writer.write(dtm, monitor)
    c_file_writer.close()
