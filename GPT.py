import struct

from PartTypeGUID import partition_type_description
from LBA import read_lba, LBA_SIZE_BYTES
from ByteHelpers import bytes_hexstr
from Debug import DEBUG, DEBUG_BYTES

PARTITION_TABLE_HEADER_SIGNATURE = "EFI PART"
PARTITION_TYPE_GUID_UNUSED = '00000000-0000-0000-0000-000000000000'

ENTRY_SIZE_BYTES = 128
NB_PARTITION_ENTRIES = 128
PARTITION_ENTRIES_PER_LBA = 4
UUID_SIZE_BYTES = 16

def get_uuid_str(uuid: bytes) -> str:
    if len(uuid) != UUID_SIZE_BYTES:
        raise ValueError("Invalid UUID length (%d)" % len(uuid))

    seg1 = struct.unpack('<I', uuid[0:4])[0]
    seg2 = struct.unpack('<H', uuid[4:6])[0]
    seg3 = struct.unpack('<H', uuid[6:8])[0]
    seg4 = struct.unpack('>H', uuid[8:10])[0]
    seg5 = struct.unpack('>Q', b'\x00\x00' + uuid[10:])[0]

    s = '%.8x-%.4x-%.4x-%.4x-%.12x' % (seg1, seg2, seg3, seg4, seg5)

    return s


def get_partition_entry(lba: bytes, entry_idx: int) -> bytes:
    if len(lba) != LBA_SIZE_BYTES:
        raise ValueError("Invalid LBA size (%d)" % len(lba))

    if not (0 <= entry_idx <= 3):
        raise ValueError("Invalid entry_idx (%d)" % entry_idx)

    entry_bytes = lba[entry_idx*ENTRY_SIZE_BYTES : (entry_idx+1)*ENTRY_SIZE_BYTES]

    return entry_bytes


def analyze_header(header_bytes: bytes) -> None:
    if len(header_bytes) != LBA_SIZE_BYTES:
        raise ValueError("Invalid header length (%d)" % len(header_bytes))

    DEBUG("Header:")
    DEBUG_BYTES(header_bytes)

    signature_str = str(header_bytes[0:8], encoding='ascii')
    revision_tuple = struct.unpack('<HH', header_bytes[8:12])
    header_size = struct.unpack('<I', header_bytes[12:16])[0]
    crc32 = struct.unpack('<I', header_bytes[16:20])[0]
    reserved = struct.unpack('<I', header_bytes[20:24])[0]
    current_lba_idx = struct.unpack('<Q', header_bytes[24:32])[0]
    backup_lba_idx = struct.unpack('<Q', header_bytes[32:40])[0]
    first_usable_lba_idx = struct.unpack('<Q', header_bytes[40:48])[0]
    last_usable_lba_idx = struct.unpack('<Q', header_bytes[48:56])[0]
    disk_guid_str = get_uuid_str(header_bytes[56:72])
    starting_lba_partition_entries_idx = struct.unpack('<Q', header_bytes[72:80])[0]
    nb_partition_entries = struct.unpack('<I', header_bytes[80:84])[0]
    partition_entry_size = struct.unpack('<I', header_bytes[84:88])[0]
    crc32_partition_entries = struct.unpack('<I', header_bytes[88:92])[0]
    reserved_tail_bytes = header_bytes[92:LBA_SIZE_BYTES]

    print("    Signature: %s" % signature_str)
    print("    Revision: %d.%d" % (revision_tuple[1], revision_tuple[0]))
    print("    Header size: %d" % header_size)
    print("    CRC32: %d" % crc32)
    print("    Reserved: %d" % reserved)
    print("    Current LBA: %d" % current_lba_idx)
    print("    Backup LBA: %d" % backup_lba_idx)
    print("    First usable LBA for partitions: %d" % first_usable_lba_idx)
    print("    Last usable LBA for partitions: %d" % last_usable_lba_idx)
    print("    Disk GUID: %s" % disk_guid_str)
    print("    Starting LBA of array of partition entries: %d" % starting_lba_partition_entries_idx)
    print("    Number of partition entries in array: %d" % nb_partition_entries)
    print("    Size of a single partition entry: %d" % partition_entry_size)
    print("    CRC32 of partition entries array: %d" % crc32_partition_entries)
    print("    Reserved: %s" % bytes_hexstr(reserved_tail_bytes))


def analyze_partition_entry_attributes(attributes: int) -> None:
    if not (0 <= attributes < 2**64):
        raise ValueError("Invalid attributes (%d)" % attributes)

    if attributes & 1:
        print("        Platform required")
    if attributes & 2:
        print("        EFI firmware should ignore the content of the partition and not try to read from it")
    if attributes & 4:
        print("        Legacy BIOS bootable")

    reserved = (attributes >> 3) & 0x1FFFFFFFFFFF
    print("        Reserved: %d" % reserved)

    specific = (attributes >> 48) & 0xFFFF
    print("        Specific: %d" % specific)


def analyze_partition_entry(entry_bytes: bytes) -> None:
    if len(entry_bytes) != ENTRY_SIZE_BYTES:
        raise ValueError("Invalid partition enry length (%d)" % len(entry_bytes))

    partition_type_guid_str = get_uuid_str(entry_bytes[0:16])

    if partition_type_guid_str == PARTITION_TYPE_GUID_UNUSED:
        return

    DEBUG("Partition entry")
    DEBUG_BYTES(entry_bytes)

    unique_partition_guid_str = get_uuid_str(entry_bytes[16:32])
    first_lba_idx = struct.unpack('<Q', entry_bytes[32:40])[0]
    last_lba_idx = struct.unpack('<Q', entry_bytes[40:48])[0]
    attribute_flags = struct.unpack('<Q', entry_bytes[48:56])[0]
    partition_name_bytes = entry_bytes[56:128]
    partition_name_str = str(partition_name_bytes, encoding='utf-16le')


    print("    Partition type GUID: %s [%s]" % (partition_type_guid_str, partition_type_description(partition_type_guid_str)))
    print("    Partition GUID: %s" % unique_partition_guid_str)
    print("    First LBA: %d" % first_lba_idx)
    print("    Last LBA: %d" % last_lba_idx)
    print("    Attribute flags: %d" % attribute_flags)
    analyze_partition_entry_attributes(attribute_flags)
    print("    Partition name: %s" % partition_name_str)


def analyze_block_device(block_device: str) -> None:
    # Primary
    print("=Primary=")
    header_bytes = read_lba(block_device, 1)
    analyze_header(header_bytes)

    for i in range(NB_PARTITION_ENTRIES // PARTITION_ENTRIES_PER_LBA):
        lba_bytes = read_lba(block_device, 2 + i)

        for j in range(PARTITION_ENTRIES_PER_LBA):
            entry_bytes = get_partition_entry(lba_bytes, j)
            analyze_partition_entry(entry_bytes)

    # Backup
    print("=Backup=")
    header_bytes = read_lba(block_device, -1)
    analyze_header(header_bytes)

    for i in range(NB_PARTITION_ENTRIES // PARTITION_ENTRIES_PER_LBA):
        lba_bytes = read_lba(block_device, -33 + i)

        for j in range(PARTITION_ENTRIES_PER_LBA):
            entry_bytes = get_partition_entry(lba_bytes, j)
            analyze_partition_entry(entry_bytes)

