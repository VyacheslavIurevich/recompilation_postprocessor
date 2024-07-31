#!/bin/bash
echo "Running pylint"
git ls-files '*.py' | xargs pylint
pylint_check_status=$?
if [[ $pylint_check_status -ne 0 ]]; then
     echo "pylint fail"
     exit 1
else
     echo "pylint OK"
     exit 0
fi
