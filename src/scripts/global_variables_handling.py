"""This module contains functions that handle global variables"""

# pylint: disable = import-error
import re
from java.lang import String


def read_array(code_unit):
    """Reads an array from a listing"""
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
    """Reads a structure from a listing"""
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
    """Gets pointer declaration string"""
    address_factory = program.getAddressFactory()
    listing = program.getListing()
    variable_declaration_string = \
        f'{code_unit.getDataType().getName()} {str(code_unit.getLabel())}'
    if code_unit.getValue() is not None:
        pointer_address = address_factory.getAddress(str(code_unit.getValue()))
        pointer = listing.getCodeUnitAt(pointer_address)
        if pointer is not None and pointer.getLabel() != code_unit.getLabel():
            variable_declaration_string += f" = {pointer.getLabel()}"
        else:
            return None
    return variable_declaration_string + ';'


def get_array_declaration(code_unit):
    """Gets array declaration string"""
    array_type = code_unit.getDataType().getName()
    string_array = read_array(code_unit)
    variable_declaration_string = \
        f'{array_type[:array_type.index("[")]} {str(code_unit.getLabel())}' + \
        array_type[array_type.index("["):]
    if string_array.count("0x0") == int(array_type[array_type.index("[") + 1:-1]):
        variable_declaration_string += " = {0}"
    elif string_array is not None:
        variable_declaration_string += " = " + string_array
    return variable_declaration_string + ';'


def get_string_declaration(code_unit):
    """Gets string of the string type declaration"""
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


def get_undefined_declaration(code_unit, listing, address):
    """Gets undeclared type string declaration string"""
    code_unit_label = str(code_unit.getLabel())
    variable_declaration_string = f"undefined {code_unit_label}"
    string_comment = "// "
    string_array = ""
    counter = 0
    while True:
        if code_unit.getValue() is not None:
            for byte in code_unit.getBytes():
                counter += 1
                string_array += f"{str(byte)}, "
                try:
                    string_comment += chr(byte)
                except ValueError:
                    string_comment += " "
        else:
            counter += 1
            string_array += "0, "
            string_comment += " "
        current_address = address.add(code_unit.getLength())
        if listing.getCodeUnitAt(current_address) is None or \
                listing.getCodeUnitAt(current_address).getLabel() is not None:
            break
        address = current_address
        code_unit = listing.getCodeUnitAt(address)
    if string_array.count('0') == counter:
        variable_declaration_string = f"undefined * {code_unit_label};"
        string_comment = ""
    else:
        variable_declaration_string += f'[{counter}] = {{{string_array[:-2]}}};'
    return variable_declaration_string, address, code_unit, string_comment


def get_variable_declaration(code_unit):
    """Gets variable declaration string"""
    variable_declaration_string = f'{code_unit.getDataType().getName()} {code_unit.getLabel()}'
    if code_unit.getValue() is not None:
        variable_declaration_string += f" = {code_unit.getValue()}"
    return variable_declaration_string + ';'


def get_character_declaration(code_unit):
    """Gets character declaration string"""
    variable_declaration_string = \
        f"{code_unit.getDataType().getName()} {str(code_unit.getLabel())}"
    if code_unit.getValue() is not None:
        variable_declaration_string += f" = '{str(code_unit.getValue())}'"
    return variable_declaration_string + ';'


def get_structure_declaration(code_unit, program):
    """Gets structure declaration string"""
    variable_declaration_string = \
        f"{code_unit.getDataType().getName()} {code_unit.getLabel()}"
    component = code_unit.getComponent(0)
    if component.getValue() is not None:
        variable_declaration_string += f" = {read_structure(code_unit, program)}"
    return variable_declaration_string + ';'


def exclude_global_variable(code_unit):
    """Excludes non-needed global variables"""
    if code_unit.getLabel() is None or len(code_unit.getSymbols()) > 1:
        return True
    if re.search(r'[^\w\s]', code_unit.getLabel()):
        return True
    for reference in code_unit.getReferenceIteratorTo():
        if reference.getFromAddress().getAddressSpace().getName() == "_elfSectionHeaders":
            return True
    return False


def put_global_variables(program, file_writer, section):
    """Puts global variables into C code file"""
    listing = program.getListing()
    data = program.getMemory().getBlock(section)

    current_address = data.getStart()
    end = current_address.add(data.getSize())
    while current_address != end:
        code_unit = listing.getCodeUnitAt(current_address)

        if exclude_global_variable(code_unit):
            current_address = current_address.add(code_unit.getLength())
            continue

        # print(code_unit.getDataType().getName(), code_unit.getLabel(),\
        #  code_unit.getValue(), code_unit.getAddress())
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
            (variable_declaration_string, current_address, code_unit, comment) = \
                get_undefined_declaration(code_unit, listing, current_address)
            file_writer.println(variable_declaration_string)
            file_writer.println(repr(comment)[1:-1])
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
