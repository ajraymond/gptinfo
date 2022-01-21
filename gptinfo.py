#!/usr/bin/env python3

import sys
import math


DEBUG = True

ENTRY_SIZE_BYTES = 128
LBA_SIZE_BYTES = 512
NB_PARTITION_ENTRIES = 128
PARTITION_ENTRIES_PER_LBA = 4


def DEBUG(msg: str):
    if DEBUG:
        print("DEBUG: %s" % msg)


def DEBUG_BYTES(b: bytes) -> None:
    bytes_per_line = 64
    nb_lines = math.ceil(len(b) / bytes_per_line)

    for line_idx in range(nb_lines):
        line_b = b[line_idx*bytes_per_line : (line_idx+1)*bytes_per_line]
        line_b_hex_str = ' '.join('%.2x' % a for a in line_b)
        line_addr = line_idx * bytes_per_line

        DEBUG("%d: %s" % (line_addr, line_b_hex_str))


def print_error_exit(error_msg: str = None):
    if error_msg:
        print(error_msg)

    print("%s <gpt_block_dev>" % sys.argv[0])
    print("    gpt_block_dev: block device containing GPT metadata")

    sys.exit(1)


def read_logical_block(f, lba_idx: int) -> bytes:
    if not ((1 <= lba_idx <= 33) or (-33 <= lba_idx <= -1)):
        raise ValueError("Invalid lba_idx (%d)" % lba_idx)

    if lba_idx >= 0:
        f.seek(lba_idx, 0)
    else:
        f.seek(lba_idx, 2)

    block_bytes = f.read(LBA_SIZE_BYTES)

    return block_bytes


def get_logical_block_entry(lba: bytes, entry_idx: int) -> bytes:
    if len(lba) != LBA_SIZE_BYTES:
        raise ValueError("Invalid LBA size (%d)" % len(lba))

    if not (0 <= entry_idx <= 3):
        raise ValueError("Invalid entry_idx (%d)" % entry_idx)

    entry_bytes = lba[entry_idx*ENTRY_SIZE_BYTES : (entry_idx+1)*ENTRY_SIZE_BYTES]

    return entry_bytes


def analyze_block_device(f) -> None:
    primary_header = read_logical_block(f, 1)
    DEBUG("Primary header:")
    DEBUG_BYTES(primary_header)

    for i in range(NB_PARTITION_ENTRIES // PARTITION_ENTRIES_PER_LBA):
        lba_bytes = read_logical_block(f, 1 + i)

        for j in range(PARTITION_ENTRIES_PER_LBA):
            entry_idx = i*PARTITION_ENTRIES_PER_LBA + j
            DEBUG("Partition entry %d" % entry_idx)
            entry_bytes = get_logical_block_entry(lba_bytes, j)
            DEBUG_BYTES(entry_bytes)


def main():
    if len(sys.argv) != 2:
        print_error_exit()

    block_device = sys.argv[1]

    with open(block_device, 'rb') as f:
        DEBUG("Analyzing %s" % block_device)
        analyze_block_device(f)


if __name__ == '__main__':
    main()

