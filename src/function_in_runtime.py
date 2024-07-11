'''Check if input function is in runtime'''

#pylint: disable=wrong-import-order
import pyhidra # pylint: disable=import-error
pyhidra.start()
#from ghidra.program.model.listing import Function  pylint: disable=import-error

def function_in_runtime(function):
    '''All runtime functions' names do start with _ '''
    function_name = function.getName()
    return function_name.startswith('_')
