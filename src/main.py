"""Postprocessor main"""

# pylint: disable=wrong-import-position, import-error
import pyhidra
pyhidra.start()
from java.io import File, PrintWriter
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
import tools


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
        tools.write_program_data_types(program, c_file_writer, flat_api.monitor)
        for function in program.getFunctionManager().getFunctions(True):
            if tools.exclude_function(function):
                continue
            results = decompiler.decompileFunction(function, 0, flat_api.monitor)
            c_file_writer.println(results.getDecompiledFunction().getC())
        c_file_writer.close()


export_c_code("resources/in/test.out", "resources/out/test.c")
