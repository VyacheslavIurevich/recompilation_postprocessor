"""User scenario tests"""
# pylint: disable=import-error, unused-argument, redefined-outer-name
import os
import pytest
from src.scripts.main import export_c_code

INPUT_DIRECTORY = "res/in/"
OUTPUT_PATH = "res/out/code.c"
COMPILER = "gcc-13"


@pytest.fixture(scope='module')
def chores():
    """Create output directory before running tests
    deleting a.out and code.c files after running tests"""
    os.makedirs("res/out", exist_ok = True)
    yield
    os.remove("a.out")
    os.remove(OUTPUT_PATH)


def compile_binary(binary):
    """Takes binary name and compiles it"""
    path = f"{INPUT_DIRECTORY}{binary}"
    export_c_code(path, OUTPUT_PATH)
    return os.system(f"{COMPILER} {OUTPUT_PATH}")


def test_hello_world(chores):
    """Recompiles hello world binary"""
    assert compile_binary("hello_world") == 0

def test_bmp(chores):
    """Recompiles BMP header reader binary"""
    assert compile_binary("bmp1") == 0

def test_bst(chores):
    """Recompiles binary search tree binary"""
    assert compile_binary("bst") == 0

def test_avl(chores):
    """Recompiles AVL tree binary"""
    assert compile_binary("avl") == 0

def test_linpack(chores):
    """Recompiles linpack binary"""
    assert compile_binary("linpack") == 0

def test_export_c_code(chores):
    """Postprocessor test"""
    for binary in os.listdir(INPUT_DIRECTORY):
        export_c_code(f"{INPUT_DIRECTORY}{binary}", OUTPUT_PATH)
    assert True
