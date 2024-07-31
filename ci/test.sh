#!/bin/bash
mkdir res/out
pytest src/tests/user_tests.py
pytest_check_status=$?
if [[ $pytest_check_status -ne 0 ]]; then
     exit 1
else
     exit 0
fi
