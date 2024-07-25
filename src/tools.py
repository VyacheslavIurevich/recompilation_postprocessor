"""Tools for checking functions and exporting decompiled program to a .c file"""

# pylint: disable=wrong-import-position, import-error, wrong-import-order
import function_code_handling
import function_handling
import re
import pyhidra

pyhidra.start()
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.data import DataTypeWriter

CONCAT_LEN = 6  # = len("CONCAT")
BYTE_SIZE = 8


def put_program_data_types(program, file_writer, monitor):
    """Dumps program data types"""
    dtm = program.getDataTypeManager()
    data_type_writer = DataTypeWriter(dtm, file_writer)
    data_type_list = []
    for data_type in dtm.getAllDataTypes():
        if ".h" not in data_type.getPathName().split('/')[1]:
            data_type_list.append(data_type)
    data_type_writer.write(data_type_list, monitor)
    dtm.close()


def init_decompiler(program):
    """Initializes decompiler"""
    options = DecompileOptions()
    options.grabFromProgram(program)
    decompiler = DecompInterface()
    decompiler.setOptions(options)
    decompiler.openProgram(program)
    return decompiler


def exclude_function(function):
    """Dumping program data types"""
    entry_point = function.getEntryPoint()
    code_unit_at = function.getProgram().getListing().getCodeUnitAt(entry_point)
    return function_handling.function_in_runtime(function) \
        or function_handling.function_is_plt(function) \
        or code_unit_at.getMnemonicString() == "??"


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
        first_inttype_size =\
            function_code_handling.get_nearest_lower_power_2(first_size * BYTE_SIZE)
        second_inttype_size =\
            function_code_handling.get_nearest_lower_power_2(second_size * BYTE_SIZE)
        concat_name = f"unsigned long CONCAT{first_size}{second_size}"
        concat_args = f"(uint{first_inttype_size}_t a, uint{second_inttype_size}_t b)\n"
        concat_body = \
            f"return ((unsigned long)b) | (unsigned long)a << ({second_size} * {BYTE_SIZE});"
        concat_signature = concat_name + concat_args
        concat_function = concat_signature + '{' + '\n' + '\t' + concat_body + '\n' + '}' + '\n'
        file_writer.println(concat_function)
        used_concats.add((first_size, second_size))
    return used_concats


def function_filter(program, monitor, decompiler):
    """Function filtering"""
    functions_code = []
    signatures_code = []
    single_return_functions = []
    name_main = ""
    for function in program.getFunctionManager().getFunctions(True):
        if exclude_function(function):
            continue
        results = decompiler.decompileFunction(function, 0, monitor)
        decompiled_function = results.getDecompiledFunction()
        function_signature = decompiled_function.getSignature()
        function_signature_processed = function_code_handling.replace_types(function_signature)
        function_code = decompiled_function.getC()
        if name_main == "" and "__libc_start_main" in function_code:
            match = re.findall(r'__libc_start_main\(\w*[^\w]', function_code)
            # print(list(match))
            # print(list(match)[0].split('(')[1][:-1])
            name_main = list(match)[0].split('(')[1][:-1]
            continue
        if function_code_handling.is_single_return(function_code, function_signature):
            single_return_functions.append(function)
            continue
        if function_code_handling.exclude_function_code(function,
                                                        single_return_functions, monitor):
            continue
        function_code_processed = function_code_handling.handle_function(function_code)
        functions_code.append(function_code_processed)
        signatures_code.append(function_signature_processed + '\n')
    return signatures_code, functions_code, name_main


def put_signatures(signatures_code, name_main, file_writer):
    """Writing functions and their signatures to a file"""
    for signature in signatures_code:
        if name_main != "" and name_main in signature:
            file_writer.println(signature.replace(name_main, "main"))
        else:
            file_writer.println(signature)


def put_functions_code(functions_code, file_writer, name_main):
    """Puts functions' code to C code file"""
    used_concats = set()
    for function_code in functions_code:
        if "CONCAT" in function_code:
            used_concats = \
                put_concat(file_writer, function_code, used_concats)
        if name_main != "" and name_main in function_code:
            file_writer.println(function_code.replace(name_main, "main"))
        else:
            file_writer.println(function_code)
