#!/bin/bash
echo "Running shellcheck"
git ls-files '*.sh' | xargs shellcheck
