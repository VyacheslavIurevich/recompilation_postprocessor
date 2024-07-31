#!/bin/bash
echo "Run tests"
mkdir res/out
pytest src/tests/user_tests.py
pytest_check_status=$?
if [[ $pytest_check_status -ne 0 ]]; then
     echo "Tests fail"
     exit 1
else
     echo "Tests OK"
     exit 0
fi
