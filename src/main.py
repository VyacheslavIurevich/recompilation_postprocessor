"""Postprocessor main"""

# pylint: disable=wrong-import-position, import-error
import pyhidra

pyhidra.start()
from java.io import File, PrintWriter
from ghidra.app.decompiler import DecompileOptions, DecompInterface
import tools

LIBRARY_LIST = ["stdio.h", "stdlib.h", "inttypes.h"]


def export_c_code(binary_file_path, output_file_path):
    """Exporting c code to a file"""
    with pyhidra.open_program(binary_file_path) as flat_api:
        program = flat_api.getCurrentProgram()
        options = DecompileOptions()
        options.grabFromProgram(program)

        decompiler = DecompInterface()
        decompiler.setOptions(options)
        decompiler.openProgram(program)

        f = File(output_file_path)
        c_file_writer = PrintWriter(f)
        for lib in LIBRARY_LIST:
            c_file_writer.println(f"#include <{lib}>")
        tools.write_program_data_types(program, c_file_writer, flat_api.monitor)
        functions_code = []
        for function in program.getFunctionManager().getFunctions(True):
            if tools.exclude_function(function):
                continue
            results = decompiler.decompileFunction(function, 0, flat_api.monitor)
            decompiled_function = results.getDecompiledFunction()
            function_signature = decompiled_function.getSignature()
            function_code = decompiled_function.getC()
            function_code_replaced_types = tools.replace_types(function_code)
            functions_code.append(function_code_replaced_types)
            c_file_writer.println(function_signature + '\n')
        used_concats = set()
        for function_code in functions_code:
            if "CONCAT" in function_code:
                used_concats = \
                    tools.put_concat(c_file_writer, function_code, used_concats)
            c_file_writer.println(function_code)
        c_file_writer.close()
        decompiler.closeProgram()
        decompiler.dispose()


export_c_code("resources/in/bmp-header.out", "resources/out/test.c")
