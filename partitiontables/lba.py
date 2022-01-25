LBA_SIZE_BYTES = 512

def read_lba(filename: str, index: int) -> bytes:
    """
    Read a 512-byte LBA block

    :param filename: name of block device to read from
    :param index: positive (0=first) or negative (-1=last) block to read
    :return: bytes object of size 512
    """

    with open(filename, 'rb') as f:
        if index >= 0:
            f.seek(index*LBA_SIZE_BYTES, 0)
        else:
            f.seek(index*LBA_SIZE_BYTES, 2)

        block_bytes = f.read(LBA_SIZE_BYTES)

    return block_bytes

