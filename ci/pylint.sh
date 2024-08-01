#!/bin/bash
echo "Running pylint"
git ls-files '*.py' | xargs pylint
