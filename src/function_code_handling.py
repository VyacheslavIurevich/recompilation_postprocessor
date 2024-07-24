"""This module contains functions that handle functions' decompiled code"""
from collections import OrderedDict
from fnmatch import fnmatch
import re

TYPES_TO_REPLACE = OrderedDict(uint="unsigned int",
                               ushort="unsigned short",
                               ulong="unsigned long",
                               undefined2="uint16_t",
                               undefined3="uint32_t",
                               undefined5="uint64_t",
                               undefined6="uint64_t",
                               undefined7="uint64_t")
STACK_PROTECTOR_VARIABLE = "in_FS_OFFSET"


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
    num_pattern = r"(?<!\w)\d*|0x\d*"
    var_pattern = r"(?<!\w)[^\d]\w*"
    for num, line in enumerate(lines):
        if fnmatch(line, "[*] = (*  [[]*[]])*;"):
            array_size, value = re.findall(num_pattern, line)
            var = re.findall(var_pattern, line)[0]
            lines[num] = f"memset(&{var}, {value}, {array_size})"

        if fnmatch(line, "[*](* ([*]) [[]*[]])(*) = (*  [[]*[]])*;"):
            matches = re.findall(num_pattern, line)
            array_size, offset, value = matches[0], matches[1], matches[3]
            var = re.findall(var_pattern, line)[1]
            lines[num] = f"memset({var} + {offset}, {value}, {array_size})"

    return '\n'.join(lines)


PATTERN_HANDLERS = (remove_stack_protection,)


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
