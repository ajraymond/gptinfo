import math

from bytehelpers import bytes_hexstr


DEBUG_ENABLED = False


def enable_debug(enabled: bool) -> None:
    DEBUG_ENABLED = enabled


def DEBUG(msg: str):
    if DEBUG_ENABLED:
        print("DEBUG: %s" % msg)


def DEBUG_BYTES(b: bytes) -> None:
    bytes_per_line = 64
    nb_lines = math.ceil(len(b) / bytes_per_line)

    for line_idx in range(nb_lines):
        line_b = b[line_idx*bytes_per_line : (line_idx+1)*bytes_per_line]
        line_b_hex_str = bytes_hexstr(line_b)
        line_addr = line_idx * bytes_per_line

        DEBUG("%d: %s" % (line_addr, line_b_hex_str))

