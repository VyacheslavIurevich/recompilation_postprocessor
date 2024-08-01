"""Tools for exporting decompiled program to a .c file"""


# pylint: disable=wrong-import-position, import-error, wrong-import-order
from src.scripts import function_code_handling
from src.scripts import function_handling
import re
import pyhidra

pyhidra.start()
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.data import DataTypeWriter
from ghidra.framework import Application
from ghidra.program.model.data import Structure
from ghidra.program.model.data import Union

CONCAT_LEN = 6  # = len("CONCAT")
BYTE_SIZE = 8


def put_program_data_types(program, file_writer, monitor, library_list):
    """Dumps program data types"""
    dtm = program.getDataTypeManager()
    data_type_list = []
    libc = {}
    typedefs = []
    with open(Application.getApplicationRootDirectory().getAbsolutePath()\
        + "/Features/Base/data/parserprofiles/clib.prf", 'r', encoding="utf-8") as f:
        for line in f:
            if line == '\n':
                break
            header = line.replace("\n", "")
            libc[header.split('\\')[-1]] = header.replace("\\", "/")
    for data_type in dtm.getAllDataTypes():
        header_name = data_type.getPathName().split('/')[1]
        if ".h" not in data_type.getPathName() and\
            "ELF" not in data_type.getPathName():
            data_type_list.append(data_type)
        elif ".h" in data_type.getPathName():
            if isinstance(data_type, Structure):
                typedefs.append(f"typedef struct {data_type.getDisplayName()}"
                                f" struct_{data_type.getDisplayName()};")
                data_type.setName(f"struct {data_type.getDisplayName()}")
            elif isinstance(data_type, Union):
                typedefs.append(f"typedef union {data_type.getDisplayName()}"
                                f" union_{data_type.getDisplayName()};")
                data_type.setName(f"union {data_type.getDisplayName()}")
            if header_name not in library_list and\
                header_name in libc:
                library_list.add(header_name)
                file_writer.println(f"#include <{libc[header_name]}>")
    for typedef in typedefs:
        file_writer.println(typedef)
    data_type_writer = DataTypeWriter(dtm, file_writer)

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


def function_filter(program, monitor, decompiler):
    """Function filtering"""
    functions_code = []
    signatures_code = []
    single_return_functions = []
    name_main = ""
    for function in program.getFunctionManager().getFunctions(True):
        if function_handling.exclude_function(function):
            continue
        results = decompiler.decompileFunction(function, 0, monitor)
        decompiled_function = results.getDecompiledFunction()
        function_signature = decompiled_function.getSignature()
        function_signature_processed = function_code_handling.replace_types(function_signature)
        function_code = decompiled_function.getC()
        if name_main == "" and "__libc_start_main" in function_code:
            match = re.findall(r'__libc_start_main\(\w*[^\w]', function_code)
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
    namespace_functions = set()
    for signature in signatures_code:
        if name_main != "" and name_main in signature:
            file_writer.println(signature.replace(name_main, "main"))
        elif "::" in signature:
            function_name = signature.split()[1].split('(')[0]
            namespace_functions.add((function_name, function_name.replace("::", "__")))
            file_writer.println(signature.replace("::", "__"))
        else:
            file_writer.println(signature)
    return namespace_functions


def put_functions_code(functions_code, file_writer, name_main, namespace_functions):
    """Puts functions' code to C code file"""
    internal_decomp_funcs = set()
    for function_code in functions_code:
        internal_decomp_funcs =\
              function_code_handling.put_internal_decomp_functions(
                  file_writer, function_code, internal_decomp_funcs)
        function_code_processed = function_code
        for namespace_function_name, new_name in namespace_functions:
            function_code_processed =\
                function_code_processed.replace(namespace_function_name, new_name)
        if name_main != "" and name_main in function_code:
            file_writer.println(function_code_processed.replace(name_main, "main"))
        else:
            file_writer.println(function_code_processed)
