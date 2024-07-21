"""Postprocessor main"""

# pylint: disable=wrong-import-position, import-error, disable=wrong-import-order
import pyhidra
import tools
from java.io import File, PrintWriter

LIBRARY_LIST = ("stdio.h", "stdlib.h", "inttypes.h", "stdbool.h")
SECTIONS = (".bss", ".rodata", ".data")

def export_c_code(binary_file_path, output_file_path):
    """Exporting c code to a file"""
    with pyhidra.open_program(binary_file_path) as flat_api:
        program = flat_api.getCurrentProgram()

        f = File(output_file_path)
        c_file_writer = PrintWriter(f)
        for lib in LIBRARY_LIST:
            c_file_writer.println(f"#include <{lib}>")
        tools.write_program_data_types(program, c_file_writer, flat_api.monitor)
        for section in SECTIONS:
            tools.write_global_variables(program, c_file_writer, section)
            c_file_writer.println()
        tools.put_functions(program, c_file_writer, flat_api.monitor)
        c_file_writer.close()


export_c_code("resources/in/global_variable", "resources/out/test.c")
