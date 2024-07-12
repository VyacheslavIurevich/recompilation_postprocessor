'''Tools for checking functions and exporting decompiled program to a .c file'''

#pylint: disable=wrong-import-order, wrong-import-position, import-error
from elftools.elf.elffile import ELFFile
from ghidra.program.model.data import DataTypeWriter

def function_in_runtime(function):
    '''Check if input function is from C Runtime'''
    function_name = function.getName()
    return function_name.startswith('_')

def get_got_bounds(path):
    '''Get GOT section addresses bounds'''
    with open(path, "rb") as file:
        elf = ELFFile(file)
        section = elf.get_section_by_name('.got')
        return section.header.sh_addr, section.header.sh_addr + section.header.sh_size - 2

def function_is_plt(function, path):
    '''Check if input function is PLT jump'''
    program = function.getProgram()
    image_base = int(str(program.getImageBase()), 16)
    listing = program.getListing()
    body = function.getBody()
    got_start, got_end = get_got_bounds(path)
    for address in body.getAddresses(True):
        code_unit = str(listing.getCodeUnitAt(address))
        if code_unit.startswith("JMP qword ptr"):
            words = code_unit.split()
            address_str = words[-1][1:-1] # removing []
            address = int(address_str, 16)
            return got_start <= address - image_base <= got_end
    return False

def write_program_data_types(program, c_file_writer, monitor):
    """Dumping program data types"""
    dtm = program.getDataTypeManager()
    data_type_writer = DataTypeWriter(dtm, c_file_writer, False)
    data_type_writer.write(dtm, monitor)

def exclude_function(function, binary_file_path):
    """Dumping program data types"""
    entry_point = function.getEntryPoint()
    code_unit_at = function.getProgram().getListing().getCodeUnitAt(entry_point)
    return \
        function_in_runtime(function) or \
        function_is_plt(function, binary_file_path) or \
        code_unit_at.getMnemonicString() == "??"
