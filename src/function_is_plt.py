'''Check if input function is PLT jump'''

#pylint: disable=wrong-import-order
import pyhidra # pylint: disable=import-error
from elftools.elf.elffile import ELFFile # pylint: disable=import-error
pyhidra.start()

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
    for address in body.getAddresses(True):
        code_unit = str(listing.getCodeUnitAt(address))
        if code_unit.startswith("JMP qword ptr"):
            words = code_unit.split()
            address_str = words[-1][1:-1] # removing []
            address = int(address_str, 16)
            got_start, got_end = get_got_bounds(path)
            return got_start <= address - image_base <= got_end
    return False
