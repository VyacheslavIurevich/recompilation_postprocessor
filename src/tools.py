"""Tools for checking functions and exporting decompiled program to a .c file"""

# pylint: disable=wrong-import-order, wrong-import-position, import-error

from collections import OrderedDict
from math import floor, log2
import re
import pyhidra
pyhidra.start()
from ghidra.program.model.scalar import Scalar
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.data import DataTypeWriter
from ghidra.pcode.floatformat import BigFloat
from ghidra.program.model.data import Array
from java.lang import String


TYPES_TO_REPLACE = OrderedDict(uint="unsigned int",
                               ushort="unsigned short",
                               ulong="unsigned long")
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


def init_decompiler(program):
    """Decompiler initialization"""
    options = DecompileOptions()
    options.grabFromProgram(program)
    decompiler = DecompInterface()
    decompiler.setOptions(options)
    decompiler.openProgram(program)
    return decompiler


def put_functions(program, file_writer, monitor):
    """Puts all functions and their signatures into C code file"""
    decompiler = init_decompiler(program)
    functions_code = []
    for function in program.getFunctionManager().getFunctions(True):
        if exclude_function(function):
            continue
        results = decompiler.decompileFunction(function, 0, monitor)
        decompiled_function = results.getDecompiledFunction()
        function_signature = decompiled_function.getSignature()
        function_signature_replaced_types = replace_types(function_signature)
        function_code = decompiled_function.getC()
        function_code_replaced_types = replace_types(function_code)
        functions_code.append(function_code_replaced_types)
        file_writer.println(function_signature_replaced_types + '\n')
    used_concats = set()
    for function_code in functions_code:
        if "CONCAT" in function_code:
            used_concats = \
                put_concat(file_writer, function_code, used_concats)
        file_writer.println(function_code)
    decompiler.closeProgram()
    decompiler.dispose()


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


def read_array(listing, code_unit):
    """Reading an array from a listing"""
    array = ""
    element_count = code_unit.getNumComponents()
    component_length = int(code_unit.getLength() / element_count)
    if (str(code_unit.getDataType().getName()).count('[')) == 1:
        for i in range(element_count):
            element = code_unit.getComponentContaining(component_length * i).getValue()
            if element is None:
                return None
            array += str(element) + ', '
        return "{" + array[:-2] + "}"
    for i in range(element_count):
        current_array = read_array(listing, code_unit.getComponentContaining(component_length * i))
        if current_array is None:
            return None
        array += current_array + ", "
    return "{" +  array[:-2] + "}"


def get_pointer_declaration(code_unit, program):
    """Get the pointer declaration string"""
    address_factory = program.getAddressFactory()
    listing = program.getListing()
    variable_declaration_string = code_unit.getDataType().getName() + " " +\
        str(code_unit.getLabel())
    if code_unit.getValue() is not None:
        pointer_address = address_factory.getAddress(str(code_unit.getValue()))
        pointer = listing.getCodeUnitAt(pointer_address)
        if pointer.getLabel() != code_unit.getLabel() and\
            re.sub(r'[^\w\s]', '_', pointer.getLabel())[:-9] != code_unit.getLabel()[:-9]:
            variable_declaration_string += " = &" + pointer.getLabel()
        else:
            return None
    return variable_declaration_string + ';'

def get_array_declaration(code_unit, listing):
    """Get the array declaration string"""
    array_type = code_unit.getDataType().getName()
    string_array = read_array(listing, code_unit)
    variable_declaration_string = array_type[:array_type.index("[")] + " " +\
        str(code_unit.getLabel()) + array_type[array_type.index("["):]
    if string_array is not None:
        variable_declaration_string += " = " + string_array
    return variable_declaration_string + ';'


def get_string_declaration(code_unit):
    """Get the string of the string declaration"""
    variable_declaration_string = "char " + str(code_unit.getLabel())
    if code_unit.getValue() is not None:
        value_of_string = str(code_unit.getValue())
        label = str(code_unit.getLabel()[2:-9]).replace('_', ' ')
        variable_declaration_string += f"[{len(value_of_string) + 1}]" +\
            ' = "' + value_of_string + '"'
        if len(label) != 0 and label in " ".join(str(code_unit.getValue()).split()):
            return None
    elif code_unit.isArray():
        array_type = code_unit.getDataType().getName()
        variable_declaration_string += array_type[array_type.index("["):]
    else:
        variable_declaration_string = "char * " + str(code_unit.getLabel())
    return variable_declaration_string + ';'


def get_undefined_string_declaration(code_unit, listing, address):
    """Get an undeclared type string declaration string"""
    variable_declaration_string = "char " +  str(code_unit.getLabel())
    string_array = ""
    while True:
        string_array += chr(code_unit.getValue().getValue())
        if int(str(listing.getCodeUnitAt(address.next()).getValue()), HEX_BASE) == 0:
            break
        address = address.next()
        code_unit = listing.getCodeUnitAt(address)
    variable_declaration_string += f"[{len(string_array)}]" + ' = "' + string_array + '";'
    return (variable_declaration_string, address)

def get_variable_declaration(code_unit):
    """Get the variable declaration string"""
    variable_declaration_string = code_unit.getDataType().getName() + " " +\
        str(code_unit.getLabel())
    if code_unit.getValue() is not None:
        variable_declaration_string += " = " + str(code_unit.getValue())
    return variable_declaration_string + ';'

# pylint: disable=too-many-locals, too-many-branches, too-many-statements
def write_global_variables(program, file_writer, section):
    """Write global variables into C code"""
    listing = program.getListing()
    data = program.getMemory().getBlock(section)

    current_address = data.getStart()
    end = current_address.add(data.getSize())
    while current_address != end:
        code_unit = listing.getCodeUnitAt(current_address)
        if (code_unit.getDataType().getName() == "undefined" and\
                (str(code_unit.getValue()) == "0x0" or code_unit.getValue() is None)) or\
                len(code_unit.getSymbols()) > 1:
            current_address = current_address.add(code_unit.getLength())
            continue
        if re.search(r'\W+', code_unit.getLabel()):
            current_address = current_address.add(code_unit.getLength())
            continue
        if code_unit.isPointer():
            variable_declaration_string = get_pointer_declaration(code_unit, program)
            if variable_declaration_string is not None:
                file_writer.println(variable_declaration_string)
        elif code_unit.getValueClass() == String:
            variable_declaration_string = get_string_declaration(code_unit)
            if variable_declaration_string is not None:
                file_writer.println(repr(variable_declaration_string)[1:-1])
        elif code_unit.getValueClass() == Array:
            variable_declaration_string = get_array_declaration(code_unit, listing)
            if variable_declaration_string is not None:
                file_writer.println(variable_declaration_string)
        elif code_unit.getDataType().getName() == "undefined":
            (variable_declaration_string, current_address) =\
                get_undefined_string_declaration(code_unit, listing, current_address)
            file_writer.println(repr(variable_declaration_string)[1:-1])
        elif code_unit.getValueClass() == Scalar or code_unit.getValueClass() == BigFloat or\
            "undefined" in code_unit.getDataType().getName():
            variable_declaration_string = get_variable_declaration(code_unit)
            file_writer.println(variable_declaration_string)
        else:
            variable_declaration_string = f'/* !!! Unhandled global varible,\
                type "{code_unit.getDataType().getName()}",\n name "{code_unit.getLabel()}",\
                address "{code_unit.getAddress()}", value "{code_unit.getValue()}"!!! */'
            file_writer.println(variable_declaration_string)
        current_address = current_address.add(code_unit.getLength())
