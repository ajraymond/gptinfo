def bytes_hexstr(b: bytes) -> str:
    return ' '.join('%.2x' % a for a in b)

