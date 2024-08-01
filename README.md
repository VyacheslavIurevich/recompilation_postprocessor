# recompilation_postprocessor
![Pylint](https://github.com/VyacheslavIurevich/recompilation_postprocessor/actions/workflows/pylint.yml/badge.svg)

This script provides ability to postprocess code, which is decompiled via Ghidra, to make it recompilable.
# Technologies used
* [Python 3.12](https://www.python.org/)
* [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra)
* [Ghidra](https://github.com/NationalSecurityAgency/ghidra)

Development:
* [Pylint](https://www.pylint.org/)
* [Pytest](https://docs.pytest.org/en/stable/)
* [Shellcheck](https://www.shellcheck.net/)
# Setup
Ensure that you do have Python with installed used technologies and Ghidra app. 
Then just clone the repo 
using HTTPS:
```shell
git clone https://github.com/VyacheslavIurevich/recompilation_postprocessor.git
```
or SSH:
```shell
git clone git@github.com:VyacheslavIurevich/recompilation_postprocessor.git
```
Go to main folder of repository
```shell
cd recompilation-postprocessor
```
Create a virtual environment:
```shell
python3 -m venv .venv
source .venv/bin/activate
```
Install requirements:
```shell
pip install -r requirements.txt
```
# Usage
Run the script with input and output command line arguments.
```shell
python run.py {path to input binary} {output .c file path}
```
For example: 
```shell
python run.py res/in/hello_world res/out/hello_world.c
```
After this, you can try to compile output code. Example with GCC:
```shell
gcc res/out/hello_world.c
```
Enjoy!
# File structure
```
├── run.py # Runs the postprocessor
├──src
│  ├──scripts
│  │  ├── function_code_handling.py # Tools for decompiled code processing
│  │  ├── function_handling.py # Tools for functions processing via Ghidra API
│  │  ├── global_variables_handling.py # Tools for global variables handling
│  │  ├── main.py # Postprocessor main script
│  │  ├── dump.py # Tools for dumping code to .c file
│  │
│  ├──tests
│  │  ├── user_tests.py # User scenario tests
│  │  │
│
├──res/in # Binary files examples
│  ├── array_sort # Sorts an array of numbers https://github.com/VyacheslavIurevich/array_sort. MIT License
│  ├── avl # AVL Tree
│  ├── bmp1 # BMP header reading tool https://github.com/Sarapulov-Vas/BMP. MIT License.
│  ├── bmp1_stack-protector # BMP header reading tool, compiled with -fno-stack-protector https://github.com/Sarapulov-Vas/BMP. MIT License.
│  ├── bmp2 # BMP header reading tool (second example) https://github.com/VyacheslavIurevich/bmp-header. MIT License.
│  ├── bmp2_stack-protector # BMP header reading tool, compiled with -fno-stack-protector https://github.com/VyacheslavIurevich/bmp-header. MIT License.
│  ├── bst.out # Binary search tree
│  ├── calculator # Bigint https://github.com/VyacheslavIurevich/c_bigint. MIT License.
│  ├── coremark.exe # Coremark benchmark https://github.com/eembc/coremark. Apache License.
│  ├── dry2 # Dhrystone benchmark https://kreier.github.io/benchmark/dhrystone/. MIT License.
│  ├── dry2o # Dhrystone benchmark https://kreier.github.io/benchmark/dhrystone/. MIT License.
│  ├── dry2r # Dhrystone benchmark https://kreier.github.io/benchmark/dhrystone/. MIT License.
│  ├── echo # Linux utility "echo". GPL.
│  ├── global_variable # Global variables example
│  ├── hello_world # Hello world example
│  ├── integrate_sin # Integrating sin(x) example https://github.com/VyacheslavIurevich/sin_integral. MIT License.
│  ├── linpack # linpack benchmark https://github.com/ereyes01/linpack. MIT License.
│  ├── linpack_stack-protector # linpack benchmark, compiled with -fno-stack-protector https://github.com/ereyes01/linpack. MIT License.
│  ├── pwd # Linux utility "pwd". GPL.
│  ├── sudo # Linux utility "sudo". GPL.
```
# Team
* Vyacheslav Kochergin. [GitHub](https://github.com/VyacheslavIurevich), [Contact](https://t.me/se4life).
* Vasilii Sarapulov. [GitHub](https://github.com/Sarapulov-Vas), [Contact](https://t.me/sarpaulov).
# Project status
In development.
# Contributing
See [CONTRIBUTING.md](./CONTRIBUTING.md)
# License
See [LICENSE](./LICENSE)
