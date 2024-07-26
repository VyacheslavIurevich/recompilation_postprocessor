"""Postprocessor main"""

# pylint: disable=wrong-import-position, import-error, wrong-import-order
from shutil import rmtree
import tools
import global_variables_handling
import pyhidra
from java.io import File, PrintWriter

LIBRARY_LIST = ("stdio.h", "stdlib.h", "inttypes.h", "stdbool.h", "memory.h")
SECTIONS = (".bss", ".rodata", ".data")


def export_c_code(binary_file_path, output_file_path):
    """Exporting c code to a file"""
    with pyhidra.open_program(binary_file_path) as flat_api:
        program = flat_api.getCurrentProgram()

        f = File(output_file_path)
        c_file_writer = PrintWriter(f)
        for lib in LIBRARY_LIST:
            c_file_writer.println(f"#include <{lib}>")
        tools.put_program_data_types(program, c_file_writer, flat_api.monitor)
        decompiler = tools.init_decompiler(program)
        signatures_code, functions_code, name_main = tools.function_filter(program,\
                                                                    flat_api.monitor, decompiler)
        tools.put_signatures(signatures_code, name_main, c_file_writer)
        for section in SECTIONS:
            global_variables_handling.put_global_variables(program, c_file_writer, section)
            c_file_writer.println()
        tools.put_functions_code(functions_code, c_file_writer, name_main)
        c_file_writer.close()
        project_folder = str(flat_api.getProjectRootFolder())[:-2]  # last two symbols are :/
    rmtree(f"resources/in/{project_folder}")


export_c_code("resources/in/echo", "resources/out/echo.c")
