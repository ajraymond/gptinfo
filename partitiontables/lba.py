LBA_SIZE_BYTES = 512

def read_lba(filename: str, start_lba: int, nb_lba: int = 1) -> bytes:
    """
    Read logical blocks

    :param filename: name of block device to read from
    :param start_lba: positive (0=first) or negative (-1=last) block to read
    :param nb_lba: number of logical blocks to read
    :return: bytes object of size nb_lba*512
    """

    with open(filename, 'rb') as f:
        data = b''

        for lba in range(nb_lba):
            lba = start_lba + lba

            if lba >= 0:
                f.seek(lba*LBA_SIZE_BYTES, 0)
            else:
                f.seek(lba*LBA_SIZE_BYTES, 2)

            data += f.read(LBA_SIZE_BYTES)

    return data

