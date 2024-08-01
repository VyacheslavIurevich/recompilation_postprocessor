"""This module contains functions that handle functions' decompiled code"""
import re
from math import ceil, log2
from collections import OrderedDict

TYPES_TO_REPLACE = OrderedDict(uint="unsigned int",
                               ushort="unsigned short",
                               ulong="unsigned long",
                               int3="uint32_t",
                               int5="uint64_t",
                               int6="uint64_t",
                               int7="uint64_t",
                               undefined2="uint16_t",
                               undefined3="uint32_t",
                               undefined5="uint64_t",
                               undefined6="uint64_t",
                               undefined7="uint64_t"
                               )


STACK_PROTECTOR_VARIABLE = "in_FS_OFFSET"
BYTE_SIZE = 8


def get_nearest_higher_power_2(num):
    """Rounds a number to nearest higher power of 2"""
    return 2 ** ceil(log2(num))


def replace_types(code):
    """Replacing all Ghidra types with types from intttypes.h and standart C types"""
    for old_type, new_type in TYPES_TO_REPLACE.items():
        code = code.replace(old_type, new_type)
    return code


def remove_stack_protection(code):
    """Removes stack protection from function code"""
    if STACK_PROTECTOR_VARIABLE not in code:
        return code
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
    return '\n'.join(lines)


def replace_cast_to_memset(code):
    """Replaces some cast expressions to memset"""
    lines = code.split('\n')
    num_pattern = r"(?<!\w)(0x\d+|\d+)"
    var_pattern = type_pattern = r"(?<!\w)[^\d\(\)\[\]=\* \+]\w*"
    for num, line in enumerate(lines):
        if re.fullmatch(fr"\s*{var_pattern}\s*=\s*\({type_pattern}\s*\[\s*{num_pattern}"
                        fr"\s*]\s*\)\s*{num_pattern};\s*", line):
            array_size, value = re.findall(num_pattern, line)
            var = re.findall(var_pattern, line)[0]
            lines[num] = f"memset(&{var}, {value}, {array_size});"

        elif re.fullmatch(fr"\s*\*\s*\({type_pattern}\s*\(\*\)\s*\[{num_pattern}"
                          fr"]\)\s*\({var_pattern}\s*\+\s*{num_pattern}"
                          fr"\)\s*=\s*\({type_pattern}\s*\[{num_pattern}"
                          fr"]\)\s*{num_pattern};\s*", line):
            matches = re.findall(num_pattern, line)
            array_size, offset, value = matches[0], matches[1], matches[3]
            var = re.findall(var_pattern, line)[1]
            lines[num] = f"memset({var} + {offset}, {value}, {array_size});"

    return '\n'.join(lines)


def replace_x_y_(code):
    """Replacing variable references, of the form ._x_y_"""
    lines = code.split('\n')
    for num, line in enumerate(lines):
        match = re.findall(r'(?<!\w)[^\d()\[\]=* +][\w.]*\._\d*_\d_', line)
        if match:
            for current_variable in match:
                last_value = current_variable.split('.')[-1]
                numbers = last_value.split("_")
                lines[num] = lines[num].replace(current_variable,
                f"*(uint{get_nearest_higher_power_2(8 * int(numbers[2]))}_t *)"
                f"((unsigned char *)&{current_variable[:-(len(last_value) + 1)]} + {numbers[1]})")
    new_code = '\n'.join(lines)
    return new_code


PATTERN_HANDLERS = (remove_stack_protection, replace_cast_to_memset, replace_x_y_)


def handle_function(code):
    """Handling function code"""
    code = replace_types(code)
    for pattern_handler in PATTERN_HANDLERS:
        code = pattern_handler(code)
    return code


def line_from_body(line, signature):
    """Line is from function body if it is not a comment, is not empty,
    is not a { or } and is not its signature. Function checks that line is from body"""
    return not (line.startswith(("//", "/*")) or line == ''
                or line in "{}" or line == signature[:-1])


def is_single_return(code, signature):
    """If function body consists of single return;, it is service function.
    Function checks if function consists of single return"""
    body = [line.replace(' ', '') for line in code.split('\n') if line_from_body(line, signature)]
    return len(body) == 1 and body[0] == "return;"


def exclude_function_code(function, single_return_functions, monitor):
    """If function calls single return function, it is service function.
    Function checks if function calls single return function."""
    for single_return_function in single_return_functions:
        if function in single_return_function.getCallingFunctions(monitor):
            return True
    return False


def concat(first_size, second_size, first_type_size, second_type_size):
    """Builds CONCATXY function"""
    output_type_size = get_nearest_higher_power_2(first_size + second_size) * BYTE_SIZE
    name = f"uint{output_type_size}_t CONCAT{first_size}{second_size}"
    args = f"(uint{first_type_size}_t x, uint{second_type_size}_t y)\n"
    body = \
        f"return ((uint{output_type_size}_t)y) |"\
        f"(uint{output_type_size}_t)x << ({second_size} * {BYTE_SIZE});"
    return name + args + '{' + '\n' + '\t' + body + '\n' + '}' + '\n'


def sub(input_size, output_size, input_type_size, output_type_size):
    """Builds SUBXY function"""
    name = f"uint{output_type_size}_t SUB{input_size}{output_size}"
    args = f"(uint{input_type_size}_t x, char c)\n"
    body = f"return (uint{output_type_size}_t) (x >> c * {BYTE_SIZE});"
    return name + args + '{' + '\n' + '\t' + body + '\n' + '}' + '\n'


def zext(input_size, output_size, input_type_size, output_type_size):
    """Builds ZEXTXY function"""
    name = f"uint{output_type_size}_t ZEXT{input_size}{output_size}"
    args = f"(uint{input_type_size}_t x)\n"
    body = f"return (uint{output_type_size}_t) x;"
    return name + args + '{' + '\n' + '\t' + body + '\n' + '}' + '\n'


INTERNAL_DECOMPILER_FUNCTIONS = dict([("CONCAT", concat), ("SUB", sub), ("ZEXT", zext)])


def put_internal_decomp_functions(file_writer, code, used_functions):
    """Puts internal decompiler functions into C code. IDF means internal decompiler functions"""
    for idf_name, handler in INTERNAL_DECOMPILER_FUNCTIONS.items():
        idf_postfix_pattern = r"\d\d\("
        idf_cnt = code.count(idf_name)
        idf_idx = 0
        for _ in range(idf_cnt):
            idf_idx = code.find(idf_name, idf_idx) + len(idf_name)
            if not re.fullmatch(idf_postfix_pattern, code[idf_idx: idf_idx + 3]):
                continue
            first_size = int(code[idf_idx])
            second_size = int(code[idf_idx + 1])
            first_type_size = get_nearest_higher_power_2(first_size * BYTE_SIZE)
            second_type_size = get_nearest_higher_power_2(second_size * BYTE_SIZE)
            if f"{idf_name}{first_size}{second_size}" in used_functions:
                continue
            idf_body = handler(first_size, second_size, first_type_size, second_type_size)
            file_writer.println(idf_body)
            used_functions.add(f"{idf_name}{first_size}{second_size}")
    return used_functions
