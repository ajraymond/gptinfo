import struct

from lba import read_lba, LBA_SIZE_BYTES
from bytehelpers import bytes_hexstr
from debug import DEBUG, DEBUG_BYTES


GPT_PARTITION_TABLE_HEADER_SIGNATURE = "EFI PART"
GPT_PARTITION_ENTRY_SIZE_BYTES = 128
GPT_NB_PARTITION_ENTRIES = 128
GPT_PARTITION_ENTRIES_PER_LBA = 4
GPT_GUID_SIZE_BYTES = 16

# https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs
GPT_PARTITION_TYPE_GUID_UNUSED = '00000000-0000-0000-0000-000000000000'

GPT_PARTITION_TYPE_GUIDS = {
        # OS agnostic
        '00000000-0000-0000-0000-000000000000': "Unused entry",
        '024dee41-33e7-11d3-9d69-0008c781f39f': "MBR partition scheme",
        'c12a7328-f81f-11d2-ba4b-00a0c93ec93b': "EFI System partition",
        '21686148-6449-6e6f-744e-656564454649': "BIOS boot partition",
        'd3bfe2de-3daf-11df-ba40-e3a556d89593': "Intel Fast Flash (iFFS) partition",
        'f4019732-066e-4e12-8273-346c5641494f': "Sony boot partition",
        'bfbfafe7-a34f-448a-9a5b-6213eb736c22': "Lenovo boot partition",

        # Linux
		'0fc63daf-8483-4772-8e79-3d69d8477de4': "Linux filesystem data",
		'a19d880f-05fc-4d3b-a006-743f0f84911e': "RAID partition",
		'44479540-f297-41b2-9af7-d131d5f0458a': "Root partition (x86)",
		'4f68bce3-e8cd-4db1-96e7-fbcaf984b709': "Root partition (x86-64)",
		'69dad710-2ce4-4e3c-b16c-21a1d49abed3': "Root partition (32-bit ARM)",
		'b921b045-1df0-41c3-af44-4c6f280d3fae': "Root partition (64-bit ARM/AArch64)",
		'bc13c2ff-59e6-4262-a352-b275fd6f7172': "/boot partition",
		'0657fd6d-a4ab-43c4-84e5-0933c84b4f4f': "Swap partition",
		'e6d6d379-f507-44c2-a23c-238f2a3df928': "Logical Volume Manager (LVM) partition",
		'933ac7e1-2eb4-4f13-b844-0e14e2aef915': "/home partition",
		'3b8f8425-20e0-4f3b-907f-1a25a76f98e8': "/srv (server data) partition",
		'7ffec5c9-2d00-49b7-8941-3ea10a5586b7': "Plain dm-crypt partition",
		'ca7d7ccb-63ed-4c53-861c-1742536059cc': "LUKS partition",
		'8da63339-0007-60c0-c436-083ac8230908': "Reserved",

		# Windows
		'e3c9e316-0b5c-4db8-817d-f92df00215ae': "Microsoft Reserved Partition (MSR)",
		'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7': "Basic data partition",
		'5808c8aa-7e8f-42e0-85d2-e1e90434cfb3': "Logical Disk Manager (LDM) metadata partition",
		'af9b60a0-1431-4f62-bc68-3311714a69ad': "Logical Disk Manager data partition",
		'de94bba4-06d1-4d40-a16a-bfd50179d6ac': "Windows Recovery Environment",
		'37affc90-ef7d-4e96-91c3-2d7ae055b174': "IBM General Parallel File System (GPFS) partition",
		'e75caf8f-f680-4cee-afa3-b001e56efc2d': "Storage Spaces partition",
		'558d43c5-a1ac-43c0-aac8-d1472b2923d1': "Storage Replica partition",
}


def partition_type_description(guid: str) -> str:
	try:
		description = GPT_PARTITION_TYPE_GUIDS[guid.lower()]
	except KeyError:
		description = "Not documented"

	return description


def get_uuid_str(uuid: bytes) -> str:
    if len(uuid) != GPT_GUID_SIZE_BYTES:
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

    entry_bytes = lba[entry_idx*GPT_PARTITION_ENTRY_SIZE_BYTES : (entry_idx+1)*GPT_PARTITION_ENTRY_SIZE_BYTES]

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
    if len(entry_bytes) != GPT_PARTITION_ENTRY_SIZE_BYTES:
        raise ValueError("Invalid partition enry length (%d)" % len(entry_bytes))

    partition_type_guid_str = get_uuid_str(entry_bytes[0:16])

    if partition_type_guid_str == GPT_PARTITION_TYPE_GUID_UNUSED:
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
    print("=GPT Primary=")
    header_bytes = read_lba(block_device, 1)
    analyze_header(header_bytes)

    for i in range(GPT_NB_PARTITION_ENTRIES // GPT_PARTITION_ENTRIES_PER_LBA):
        lba_bytes = read_lba(block_device, 2 + i)

        for j in range(GPT_PARTITION_ENTRIES_PER_LBA):
            entry_bytes = get_partition_entry(lba_bytes, j)
            analyze_partition_entry(entry_bytes)

    # Backup
    print("=GPT Backup=")
    header_bytes = read_lba(block_device, -1)
    analyze_header(header_bytes)

    for i in range(GPT_NB_PARTITION_ENTRIES // GPT_PARTITION_ENTRIES_PER_LBA):
        lba_bytes = read_lba(block_device, -33 + i)

        for j in range(GPT_PARTITION_ENTRIES_PER_LBA):
            entry_bytes = get_partition_entry(lba_bytes, j)
            analyze_partition_entry(entry_bytes)

