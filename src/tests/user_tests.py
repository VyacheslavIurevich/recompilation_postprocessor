"""User scenario tests"""
import os

from src.scripts.main import export_c_code


INPUT_DIRECTORY = "resources/in/"
OUTPUT_PATH = "resources/out/code.c"
COMPILER = "gcc"


class UserTests:
    """User scenario tests"""

    def compile_binary(self, binary):
        """Takes binary name and compiles it"""
        path = f"{INPUT_DIRECTORY}{binary}"
        export_c_code(path, OUTPUT_PATH)
        return os.system(f"{COMPILER} {OUTPUT_PATH}")

    def test_hello_world(self):
        """Recompiles hello world binary"""
        assert self.compile_binary("hello_world") == 0

    def test_integrate_sin(self):
        """Recompiles sin intergrating binary"""
        assert self.compile_binary("integrate_sin") == 0

    def test_array_sort(self):
        """Recompiles array sorting binary"""
        assert self.compile_binary("array_sort") == 0

    def test_bmp(self):
        """Recompiles BMP header reader binary"""
        assert self.compile_binary("bmp1") == 0

    def test_bst(self):
        """Recompiles binary search tree binary"""
        assert self.compile_binary("bst") == 0

    def test_avl(self):
        """Recompiles AVL tree binary"""
        assert self.compile_binary("avl") == 0

    def test_linpack(self):
        """Recompiles AVL tree binary"""
        assert self.compile_binary("linpack") == 0
