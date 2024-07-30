"""This module contains functions that handle functions before decompiling"""

HEX_BASE = 16
RUNTIME_PREFIX = '_'
PLT_INSTRUCTION = "JMP qword ptr"


def address_to_int(address):
    """Converts address (hex number) to int"""
    return int(str(address), HEX_BASE)


def function_in_runtime(function):
    """Checks if input function is from C Runtime"""
    function_name = function.getName()
    return function_name.startswith(RUNTIME_PREFIX)


def function_is_plt(function):
    """Checks if input function is PLT jump"""
    program = function.getProgram()
    listing = program.getListing()
    body = function.getBody()
    min_address = address_to_int(body.getMinAddress())
    max_address = address_to_int(body.getMaxAddress())
    for address in body.getAddresses(True):
        code_unit = listing.getCodeUnitAt(address)
        if str(code_unit).startswith(PLT_INSTRUCTION):
            jmp_address = code_unit.getInputObjects()[0].getOffset()
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
