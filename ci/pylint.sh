#!/bin/bash
pylint $(git ls-files '*.py')
pylint_check_status=$?
if [[ $pylint_check_status -ne 0 ]]; then
     exit 1
else
     exit 0
fi
