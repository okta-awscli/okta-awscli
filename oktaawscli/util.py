from __future__ import print_function
import sys

try:
    _input = raw_input
except NameError:
    _input = input


def input(prompt=None):
    if not prompt:
        return _input()

    print(prompt.rstrip('\n'), end='', file=sys.stderr, flush=True)
    return _input()
