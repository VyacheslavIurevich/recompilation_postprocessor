"""User scenario tests"""
# pylint: disable=import-error, unused-argument, redefined-outer-name
import os
import pytest
from src.scripts.main import export_c_code

INPUT_DIRECTORY = "res/in/"
OUTPUT_PATH = "res/out/code.c"
COMPILER = "gcc"


@pytest.fixture(scope='module')
def clean():
    """Deleting a.out and code.c files"""
    yield
    os.remove("a.out")
    os.remove(OUTPUT_PATH)


def compile_binary(binary):
    """Takes binary name and compiles it"""
    path = f"{INPUT_DIRECTORY}{binary}"
    export_c_code(path, OUTPUT_PATH)
    return os.system(f"{COMPILER} {OUTPUT_PATH}")


class TestUser:
    """User scenario tests"""

    def test_hello_world(self, clean):
        """Recompiles hello world binary"""
        assert compile_binary("hello_world") == 0

    def test_bmp(self, clean):
        """Recompiles BMP header reader binary"""
        assert compile_binary("bmp1") == 0

    def test_bst(self, clean):
        """Recompiles binary search tree binary"""
        assert compile_binary("bst") == 0

    def test_avl(self, clean):
        """Recompiles AVL tree binary"""
        assert compile_binary("avl") == 0

    def test_linpack(self, clean):
        """Recompiles AVL tree binary"""
        assert compile_binary("linpack") == 0