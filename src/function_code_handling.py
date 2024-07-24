"""This module contains functions that handle functions' decompiled code"""
import re
from math import ceil, log2
from collections import OrderedDict

STACK_PROTECTOR_VARIABLE = "in_FS_OFFSET"
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


def replace_x_y_(code):
    """Replacing variable references, of the form ._x_y_"""
    lines = code.split('\n')
    for num, line in enumerate(lines):
        match = re.findall(r'[\W][\w\.]*\._\d*_\d_', line)
        if match:
            for i in match:
                current_variable = i[1:]
                last_value = current_variable.split('.')[-1]
                numbers = last_value.split("_")
                lines[num] = lines[num].replace(i[1:],\
                f"*(uint{get_nearest_lower_power_2(8 * int(numbers[2]))}_t *)"
                f"((unsigned char *)&{current_variable[:-(len(last_value) + 1)]} + {numbers[1]})")
    new_code = '\n'.join(lines)
    return new_code


def handle_function(code):
    """Handling function code"""
    code_replaced_types = replace_types(code)
    code_change_x_y_ = replace_x_y_(code_replaced_types)
    if STACK_PROTECTOR_VARIABLE not in code_change_x_y_:
        return code_change_x_y_
    code_removed_stack_protection = remove_stack_protection(code_change_x_y_)
    return code_removed_stack_protection


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


def calls_single_return(code, signature, single_return_functions):
    """If function calls single return function, it is service function. 
    Function checks if function calls single return function."""
    body = [line.replace(' ', '') for line in code.split('\n') if line_from_body(line, signature)]
    for function in single_return_functions:
        if function + "();" in body:
            return True
    return False
