#!/usr/bin/env python3

import sys
import getopt

import MBR
import GPT
from Debug import DEBUG, DEBUG_BYTES


def usage():
    print("Usage: %s [OPTION]... <block_device>" % sys.argv[0])
    print()
    print("Mandatory arguments:")
    print("    block_device: block device containing partition table to analyze")
    print()
    print("Options:")
    print("    -h, --help:          show this message")
    print("    -v, --verbose:       activate debug logs")


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hv",
                                   ["help, verbose"])
    except getopt.GetoptError as err:
        print(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(1)

    for o, a in opts:
        if o in ('-v', '--verbose'):
            enable_debug(True)
        elif o in ('-h', '--help'):
            usage()
            sys.exit()
        else:
            assert False, "unhandled option"

    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    block_device = sys.argv[1]
    DEBUG("Analyzing %s" % block_device)

    MBR.analyze(block_device)
    GPT.analyze_block_device(block_device)


if __name__ == '__main__':
    main()

