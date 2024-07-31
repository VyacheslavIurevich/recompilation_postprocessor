#!/bin/bash
echo "Running shellcheck"
git ls-files '*.sh' | xargs shellcheck
shellcheck_check_status=$?
if [[ $shellcheck_check_status -ne 0 ]]; then
     echo "shellcheck fail"
     exit 1
else
     echo "shellcheck OK"
     exit 0
fi
