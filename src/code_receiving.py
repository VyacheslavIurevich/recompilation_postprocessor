'''Receiving decompiled code from Ghidra API via pyhidra'''
#pylint: disable=wrong-import-position
import pyhidra # pylint: disable=import-error
pyhidra.start()
import ghidra # pylint: disable=import-error
from java.io import File # pylint: disable=import-error

def receive_code(binary_file_path, output_file_path):
    '''Receiving decompiled code'''
    with pyhidra.open_program(binary_file_path) as flat_api:
        program = flat_api.getCurrentProgram()
        dtm = program.getDataTypeManager()
        ifc = ghidra.app.decompiler.DecompInterface()
        ifc.openProgram(program)
        print(ghidra.app.util.exporter.getFakeCTypeDefinitions(dtm.getDataOrganization()))
        # for i in data_type.getDataOrganization():
        #     print(i)
        # for f in program.getFunctionManager().getFunctions(True):
        #     print(f, f.getBody())
            # print()
            # results = ifc.decompileFunction(f, 0, flat_api.monitor)
            # print(results.getDecompiledFunction().getC())

        # listing = program.getListing()
        # for i in listing.getCodeUnits(True):
        #     print(i)
        # exporter = ghidra.app.util.exporter.CppExporter()

        # f = File(output_file_path)
        # exporter.export(f, program, None, flat_api.monitor)

receive_code("resources/in/test.out", "resources/out/test.c")
