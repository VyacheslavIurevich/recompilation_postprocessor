"""Postprocessor main"""

# pylint: disable=wrong-import-position, import-error
from shutil import rmtree
import pyhidra

pyhidra.start()
from java.io import File, PrintWriter
from ghidra.app.decompiler import DecompileOptions, DecompInterface
import tools

LIBRARY_LIST = ["stdio.h", "stdlib.h", "inttypes.h"]


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
        if tools.exclude_function(function):
            continue
        results = decompiler.decompileFunction(function, 0, monitor)
        decompiled_function = results.getDecompiledFunction()
        function_signature = decompiled_function.getSignature()
        function_signature_processed = tools.replace_types(function_signature)
        function_code = decompiled_function.getC()
        if tools.is_single_return(function_code, function_signature):
            continue
        function_code_processed = tools.handle_function(function_code)
        functions_code.append(function_code_processed)
        file_writer.println(function_signature_processed + '\n')
    used_concats = set()
    for function_code in functions_code:
        if "CONCAT" in function_code:
            used_concats = \
                tools.put_concat(file_writer, function_code, used_concats)
        file_writer.println(function_code)
    decompiler.closeProgram()
    decompiler.dispose()


def export_c_code(binary_file_path, output_file_path):
    """Exporting c code to a file"""
    with pyhidra.open_program(binary_file_path) as flat_api:
        program = flat_api.getCurrentProgram()
        f = File(output_file_path)
        c_file_writer = PrintWriter(f)
        for lib in LIBRARY_LIST:
            c_file_writer.println(f"#include <{lib}>")
        tools.write_program_data_types(program, c_file_writer, flat_api.monitor)
        put_functions(program, c_file_writer, flat_api.monitor)
        c_file_writer.close()
        project_folder = str(flat_api.getProjectRootFolder())[:-2]  # last two symbols are :/
    rmtree(f"resources/in/{project_folder}")


export_c_code("resources/in/test.out", "resources/out/test.c")
