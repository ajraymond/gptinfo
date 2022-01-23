#!/usr/bin/env python3

import sys

from GPT import analyze_block_device
from Debug import DEBUG, DEBUG_BYTES


def print_usage_exit(error_msg: str = None):
    if error_msg:
        print(error_msg)

    print("%s <block_dev>" % sys.argv[0])
    print("    block_dev: block device containing partition table to analyze")

    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print_usage_exit()

    block_device = sys.argv[1]
    DEBUG("Analyzing %s" % block_device)

    analyze_block_device(block_device)


if __name__ == '__main__':
    main()

