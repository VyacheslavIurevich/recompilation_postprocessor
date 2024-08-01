"""Postprocessor main"""

# pylint: disable=wrong-import-position, import-error, wrong-import-order
from shutil import rmtree
from os.path import exists
from src.scripts import dump
from src.scripts import global_variables_handling
import pyhidra
from java.io import File, PrintWriter


SECTIONS = (".bss", ".rodata", ".data")


def export_c_code(binary_file_path, output_file_path):
    """Exporting c code to a file"""
    if not exists(binary_file_path):
        print("No such input file!")
        return
    with pyhidra.open_program(binary_file_path) as flat_api:
        program = flat_api.getCurrentProgram()
        c_file_writer = PrintWriter(File(output_file_path))
        library_list = {"stdio.h", "stdlib.h", "inttypes.h", "stdbool.h", "memory.h"}
        for lib in library_list:
            c_file_writer.println(f"#include <{lib}>")
        dump.put_program_data_types(program, c_file_writer, flat_api.monitor, library_list)
        decompiler = dump.init_decompiler(program)
        signatures_code, functions_code, name_main = dump.function_filter(program,
                                                                    flat_api.monitor, decompiler)
        namespace_functions = dump.put_signatures(signatures_code, name_main, c_file_writer)
        for section in SECTIONS:
            global_variables_handling.put_global_variables(program, c_file_writer, section)
            c_file_writer.println()
        dump.put_functions_code(functions_code, c_file_writer, name_main, namespace_functions)
        c_file_writer.close()
        project_folder = str(flat_api.getProjectRootFolder())[:-2]  # last two symbols are :/
    directory = binary_file_path[:binary_file_path.rfind('/')]
    rmtree(f"{directory}/{project_folder}")
