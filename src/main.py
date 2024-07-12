"""Postprocessor main"""

#pylint: disable=wrong-import-position
import pyhidra # pylint: disable=import-error
pyhidra.start()
import ghidra # pylint: disable=import-error
from java.io import File, PrintWriter # pylint: disable=import-error
import tools # pylint: disable=import-error

def export_c_code(binary_file_path, output_file_path):
    '''Exporting c code to a file'''
    with pyhidra.open_program(binary_file_path) as flat_api:
        program = flat_api.getCurrentProgram()
        ifc = ghidra.app.decompiler.DecompInterface()
        ifc.openProgram(program)
        f = File(output_file_path)
        c_file_writer = PrintWriter(f)
        tools.write_program_data_types(program, c_file_writer, flat_api.monitor)
        for function in program.getFunctionManager().getFunctions(True):
            if tools.exclude_function(function, binary_file_path):
                continue
            results = ifc.decompileFunction(function, 0, flat_api.monitor)
            c_file_writer.println(results.getDecompiledFunction().getC())
        c_file_writer.close()

export_c_code("resources/in/test.out", "resources/out/test.c")
