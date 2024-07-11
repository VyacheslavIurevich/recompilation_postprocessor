'''Dumping program data types'''
#pylint: disable=wrong-import-position
import pyhidra # pylint: disable=import-error
pyhidra.start()
import ghidra # pylint: disable=import-error
from java.io import PrintWriter # pylint: disable=import-error

def write_program_data_types(program, file, monitor):
    """Dumping program data types"""
    dtm = program.getDataTypeManager()
    c_file_writer = PrintWriter(file)
    data_type_writer = ghidra.program.model.data.DataTypeWriter(dtm, c_file_writer, False)
    data_type_writer.write(dtm, monitor)
    c_file_writer.close()
