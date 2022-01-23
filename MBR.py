import struct

from LBA import read_lba, LBA_SIZE_BYTES
from ByteHelpers import bytes_hexstr
from Debug import DEBUG, DEBUG_BYTES


MBR_PARTITION_ENTRY_SIZE_BYTES = 16
MBR_PARTITION_ENTRY_CHS_SIZE_BYTES = 3

# https://en.wikipedia.org/wiki/Partition_type#List_of_partition_IDs
MBR_PARTITION_TYPE_GPT_PROTECTIVE = 0xEE

MBR_PARTITION_TYPES = {
        0x00: "Unused entry",
        0xEE: "GPT Protective MBR",
}


def partition_type_description(partition_type: int) -> str:
	try:
		description = MBR_PARTITION_TYPES[partition_type]
	except KeyError:
		description = "Not documented"

	return description


def read_chs(b: bytes) -> tuple:
    if len(b) != MBR_PARTITION_ENTRY_CHS_SIZE_BYTES:
        raise ValueError("Invalid CHS size (%d)" % len(b))

    head = b[0]
    sector = b[1] & 0x3F
    cylinder = ((b[1] & 0xC) << 2) | b[2]

    return head, sector, cylinder


def analyze_partition_entry(entry_bytes: bytes) -> None:
    if len(entry_bytes) != MBR_PARTITION_ENTRY_SIZE_BYTES:
        raise ValueError("Invalid partition enry length (%d)" % len(entry_bytes))

    status = entry_bytes[0]
    first_absolute_sector_chs = read_chs(entry_bytes[1:4])
    partition_type = entry_bytes[4]
    last_absolute_sector_chs = read_chs(entry_bytes[5:8])
    first_absolute_sector_lba = struct.unpack('<I', entry_bytes[8:12])[0]
    nb_sectors = struct.unpack('<I', entry_bytes[12:16])[0]

    print("        Status: 0x%.2x" % status)
    print("        First absolute sector address (CHS): %s" % str(first_absolute_sector_chs))
    print("        Partition type: 0x%.2x (%s)" % (partition_type, partition_type_description(partition_type)))
    print("        Last absolute sector (CHS): %s" % str(last_absolute_sector_chs))
    print("        First absolute sector (LBA): %d" % first_absolute_sector_lba)
    print("        Nb sectors: %d" % nb_sectors)


def analyze(block_device: str) -> None:
    print("=MBR=")
    mbr_bytes = read_lba(block_device, 0)

    if len(mbr_bytes) != LBA_SIZE_BYTES:
        raise ValueError("Invalid MBR length (%d)" % len(mbr_bytes))

    DEBUG("MBR:")
    DEBUG_BYTES(mbr_bytes)

    bootstrap_code_1 = mbr_bytes[0:218]
    zeros = struct.unpack('<H', mbr_bytes[218:220])[0]
    original_physical_drive = mbr_bytes[220]
    seconds = mbr_bytes[221]
    minutes = mbr_bytes[222]
    hours = mbr_bytes[223]
    bootstrap_code_2 = mbr_bytes[224:440]
    disk_signature = struct.unpack('<I', mbr_bytes[440:444])[0]
    copy_protected = struct.unpack('<H', mbr_bytes[444:446])[0]
    partition_entry_1 = mbr_bytes[446:462]
    partition_entry_2 = mbr_bytes[462:478]
    partition_entry_3 = mbr_bytes[478:494]
    partition_entry_4 = mbr_bytes[494:510]
    boot_signature = struct.unpack('<H', mbr_bytes[510:512])[0]

    print("    Bootstrap code:")
    print("    %s" % bytes_hexstr(bootstrap_code_1 + bootstrap_code_2))
    print("    Zeros: %d" % zeros)
    print("    Original physical drive: 0x%.2x" % original_physical_drive)
    print("    Seconds: %d" % seconds)
    print("    Minutes: %d" % minutes)
    print("    Hours: %d" % hours)
    print("    Disk signature: %d" % boot_signature)
    print("    Copy protection: 0x%.4x" % copy_protected)
    print("    Partition 1:")
    analyze_partition_entry(partition_entry_1)
    print("    Partition 2:")
    analyze_partition_entry(partition_entry_2)
    print("    Partition 3:")
    analyze_partition_entry(partition_entry_3)
    print("    Partition 4:")
    analyze_partition_entry(partition_entry_4)
    print("    Boot signature: 0x%.4x" % boot_signature)

