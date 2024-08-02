#!/bin/bash
echo "Run tests"
mkdir -p res/out
pytest src/tests/user_tests.py
