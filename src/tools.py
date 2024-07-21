"""Tools for checking functions and exporting decompiled program to a .c file"""

# pylint: disable=wrong-import-order, wrong-import-position, import-error

from collections import OrderedDict
from math import floor, log2
import re
import pyhidra

pyhidra.start()
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.data import DataTypeWriter
from java.lang import String

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
        function_signature_processed = replace_types(function_signature)
        function_code = decompiled_function.getC()
        if is_single_return(function_code, function_signature):
            continue
        function_code_processed = handle_function(function_code)
        functions_code.append(function_code_processed)
        file_writer.println(function_signature_processed + '\n')
    used_concats = set()
    for function_code in functions_code:
        if "CONCAT" in function_code:
            used_concats = \
                put_concat(file_writer, function_code, used_concats)
        file_writer.println(function_code)
    decompiler.closeProgram()
    decompiler.dispose()


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


def read_array(code_unit):
    """Reading an array from a listing"""
    array = ""
    element_count = code_unit.getNumComponents()
    if (str(code_unit.getDataType().getName()).count('[')) == 1:
        for i in range(element_count):
            element = code_unit.getComponent(i).getValue()
            if element is None:
                return None
            array += f'{str(element)}, '
        return "{" + array[:-2] + "}"
    for i in range(element_count):
        current_array = read_array(code_unit.getComponent(i))
        if current_array is None:
            return None
        array += current_array + ", "
    return "{" + array[:-2] + "}"


def read_structure(code_unit, program):
    """Reading a structure from a listing"""
    struct = ""
    address_factory = program.getAddressFactory()
    listing = program.getListing()
    for i in range(code_unit.getNumComponents()):
        component = code_unit.getComponent(i)
        if component.isArray():
            current_component_value = read_array(component)
        elif component.getDataType().getName() == "char":
            current_component_value = f"'{str(component.getValue())}'"
        elif component.isStructure():
            current_component_value = read_structure(component, program)
        elif component.isPointer():
            pointer_address = address_factory.getAddress(str(component.getValue()))
            pointer = listing.getCodeUnitAt(pointer_address)
            current_component_value = pointer.getLabel()
        else:
            current_component_value = str(component.getValue())
        struct += f"{current_component_value}, "
    return "{" + struct[:-2] + "}"


def get_pointer_declaration(code_unit, program):
    """Get pointer declaration string"""
    address_factory = program.getAddressFactory()
    listing = program.getListing()
    variable_declaration_string = \
        f'{code_unit.getDataType().getName()} {str(code_unit.getLabel())}'
    if code_unit.getValue() is not None:
        pointer_address = address_factory.getAddress(str(code_unit.getValue()))
        pointer = listing.getCodeUnitAt(pointer_address)
        if pointer.getLabel() != code_unit.getLabel():
            variable_declaration_string += f" = {pointer.getLabel()}"
        else:
            return None
    return variable_declaration_string + ';'


def get_array_declaration(code_unit):
    """Get array declaration string"""
    array_type = code_unit.getDataType().getName()
    string_array = read_array(code_unit)
    variable_declaration_string = \
        f'{array_type[:array_type.index("[")]} {str(code_unit.getLabel())}' + \
        array_type[array_type.index("["):]
    if string_array is not None:
        variable_declaration_string += " = " + string_array
    return variable_declaration_string + ';'


def get_string_declaration(code_unit):
    """Get string of the string tpye declaration"""
    variable_declaration_string = "char " + str(code_unit.getLabel())
    if code_unit.getValue() is not None:
        value_of_string = str(code_unit.getValue())
        variable_declaration_string += f'[{len(value_of_string) + 1}] = "{value_of_string}"'
    elif code_unit.isArray():
        array_type = code_unit.getDataType().getName()
        variable_declaration_string += array_type[array_type.index("["):]
    else:
        variable_declaration_string = f"char * {str(code_unit.getLabel())}"
    return variable_declaration_string + ';'


def get_undefined_string_declaration(code_unit, listing, address):
    """Get undeclared type string declaration string"""
    variable_declaration_string = f"char {str(code_unit.getLabel())}"
    string_array = ""
    while True:
        string_array += chr(code_unit.getValue().getValue())
        if int(str(listing.getCodeUnitAt(address.next()).getValue()), HEX_BASE) == 0:
            break
        address = address.next()
        code_unit = listing.getCodeUnitAt(address)
    variable_declaration_string += f'[{len(string_array) + 1}] = "{string_array}";'
    return variable_declaration_string, address


def get_variable_declaration(code_unit):
    """Get variable declaration string"""
    variable_declaration_string = f'{code_unit.getDataType().getName()} {code_unit.getLabel()}'
    if code_unit.getValue() is not None:
        variable_declaration_string += f" = {code_unit.getValue()}"
    return variable_declaration_string + ';'


def get_character_declaration(code_unit):
    """Get character declaration string"""
    variable_declaration_string = f"{code_unit.getDataType().getName()} \
{str(code_unit.getLabel())}"
    if code_unit.getValue() is not None:
        variable_declaration_string += f" = '{str(code_unit.getValue())}'"
    return variable_declaration_string + ';'


def get_structure_declaration(code_unit, program):
    """Get structure declaration string"""
    variable_declaration_string = f"{code_unit.getDataType().getName()} \
{code_unit.getLabel()}"
    component = code_unit.getComponent(0)
    if component.getValue() is not None:
        variable_declaration_string += f" = {read_structure(code_unit, program)}"
    return variable_declaration_string + ';'


def exclude_global_variable(code_unit):
    """Exclusion of global variables"""
    if (code_unit.getDataType().getName() == "undefined" and
        (str(code_unit.getValue()) == "0x0" or code_unit.getValue() is None)) or \
            len(code_unit.getSymbols()) > 1:
        return True
    if re.search(r'[^\w\s]', code_unit.getLabel()):
        return True
    for reference in code_unit.getReferenceIteratorTo():
        if reference.getFromAddress().getAddressSpace().getName() == "_elfSectionHeaders":
            return True
    return False


def write_global_variables(program, file_writer, section):
    """Write global variables into C code"""
    listing = program.getListing()
    data = program.getMemory().getBlock(section)

    current_address = data.getStart()
    end = current_address.add(data.getSize())
    while current_address != end:
        code_unit = listing.getCodeUnitAt(current_address)
        if exclude_global_variable(code_unit):
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
        elif code_unit.isArray():
            variable_declaration_string = get_array_declaration(code_unit)
            if variable_declaration_string is not None:
                file_writer.println(variable_declaration_string)
        elif code_unit.getDataType().getName() == "undefined":
            (variable_declaration_string, current_address) = \
                get_undefined_string_declaration(code_unit, listing, current_address)
            file_writer.println(repr(variable_declaration_string)[1:-1])
        elif code_unit.getDataType().getName() == "char":
            variable_declaration_string = get_character_declaration(code_unit)
            file_writer.println(variable_declaration_string)
        elif code_unit.isStructure():
            variable_declaration_string = get_structure_declaration(code_unit, program)
            file_writer.println(variable_declaration_string)
        else:
            variable_declaration_string = get_variable_declaration(code_unit)
            file_writer.println(variable_declaration_string)
        current_address = current_address.add(code_unit.getLength())


def line_from_body(line, signature):
    """Line is from function body if it is not a comment, is not empty, 
    is not a { or } and is not its signature"""
    return not (line.startswith(("//", "/*")) or line == ''
                or line in "{}" or line == signature[:-1])


def is_single_return(code, signature):
    """If function body consists of only one return;, it is service function"""
    body = [line for line in code.split('\n') if line_from_body(line, signature)]
    return len(body) == 1 and body[0].replace(' ', '') == "return;"
