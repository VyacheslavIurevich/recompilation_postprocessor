"""This module contains functions that handle functions' decompiled code"""
import re
from math import ceil, log2
from collections import OrderedDict
from math import ceil, log2
import re

TYPES_TO_REPLACE = OrderedDict(uint="unsigned int",
                               ushort="unsigned short",
                               ulong="unsigned long",
                               undefined3="uint32_t",
                               undefined5="uint64_t",
                               undefined6="uint64_t",
                               undefined7="uint64_t",
                               int3="uint32_t",
                               int5="uint64_t",
                               int6="uint64_t",
                               int7="uint64_t")


STACK_PROTECTOR_VARIABLE = "in_FS_OFFSET"
CONCAT_LEN = 6  # = len("CONCAT")
BYTE_SIZE = 8


def get_nearest_lower_power_2(num):
    """Rounds a number to nearest lower power of 2"""
    return 2 ** ceil(log2(num))


def get_nearest_lower_power_2(num):
    """Rounds a number to nearest lower power of 2"""
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
            for i in match:
                current_variable = i[1:]
                last_value = current_variable.split('.')[-1]
                numbers = last_value.split("_")
                lines[num] = lines[num].replace(i[1:],
                f"*(uint{get_nearest_lower_power_2(8 * int(numbers[2]))}_t *)"
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
