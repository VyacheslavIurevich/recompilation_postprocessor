"""Parses command line arguments and runs the postprocessor"""
import argparse
from src.scripts.main import export_c_code

parser = argparse.ArgumentParser()
parser.add_argument("input")
parser.add_argument("output")
args = vars(parser.parse_args())
export_c_code(args["input"], args["output"])
