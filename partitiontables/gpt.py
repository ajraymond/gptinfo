import struct

from lba import read_lba, LBA_SIZE_BYTES
from bytehelpers import bytes_hexstr
from debug import DEBUG, DEBUG_BYTES


GPT_PARTITION_TABLE_HEADER_SIGNATURE = "EFI PART"
GPT_PARTITION_ENTRY_SIZE_BYTES = 128
GPT_NB_PARTITION_ENTRIES = 128
GPT_PARTITION_ENTRIES_PER_LBA = 4
GPT_GUID_SIZE_BYTES = 16
GPT_SIZE_LBA = 33

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


class GPT:
    def __init__(self):
        self.block_device = None
        self.mbr_bytes = bytes(LBA_SIZE_BYTES)
        self.primary_gpt_bytes = bytes(LBA_SIZE_BYTES*GPT_SIZE_LBA)
        self.backup_gpt_bytes = bytes(LBA_SIZE_BYTES*GPT_SIZE_LBA)

    @staticmethod
    def get_guid_str(guid: bytes) -> str:
        if len(guid) != GPT_GUID_SIZE_BYTES:
            raise ValueError("Invalid UUID length (%d)" % len(guid))

        seg1 = struct.unpack('<I', guid[0:4])[0]
        seg2 = struct.unpack('<H', guid[4:6])[0]
        seg3 = struct.unpack('<H', guid[6:8])[0]
        seg4 = struct.unpack('>H', guid[8:10])[0]
        seg5 = struct.unpack('>Q', b'\x00\x00' + guid[10:])[0]

        s = '%.8x-%.4x-%.4x-%.4x-%.12x' % (seg1, seg2, seg3, seg4, seg5)

        return s


    # Partition-level fields

    @staticmethod
    def partition_type_description(partition_guid: str) -> str:
        try:
            description = GPT_PARTITION_TYPE_GUIDS[partition_guid.lower()]
        except KeyError:
            description = "Not documented"

        return description


    def get_partition_bytes(self, partition_idx: int) -> bytes:
        if not (0 <= partition_idx <= 127):
            raise ValueError("Invalid partition index (%d)" % partition_idx)

        lba = partition_idx // GPT_PARTITION_ENTRIES_PER_LBA
        sub_lba = partition_idx % GPT_PARTITION_ENTRIES_PER_LBA

        partitions_bytes = self.primary_gpt_bytes[LBA_SIZE_BYTES:]
        start_addr = (lba * LBA_SIZE_BYTES) + (sub_lba * GPT_PARTITION_ENTRY_SIZE_BYTES)
        partition_bytes = partitions_bytes[start_addr:start_addr+GPT_PARTITION_ENTRY_SIZE_BYTES]

        return partition_bytes

    #

    def get_partition_type_guid_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[0:16]

    def get_partition_type_guid(self, partition_idx: int) -> str:
        return GPT.get_guid_str(self.get_partition_type_guid_bytes(partition_idx))

    #

    def get_partition_unique_guid_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[16:32]

    def get_partition_unique_guid(self, partition_idx: int) -> str:
        return GPT.get_guid_str(self.get_partition_unique_guid_bytes(partition_idx))

    #

    def get_partition_first_lba_idx_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[32:40]

    def get_partition_first_lba_idx(self, partition_idx: int) -> int:
        return struct.unpack('<Q', self.get_partition_first_lba_idx_bytes(partition_idx))[0]

    #

    def get_partition_last_lba_idx_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[40:48]

    def get_partition_last_lba_idx(self, partition_idx: int) -> int:
        return struct.unpack('<Q', self.get_partition_last_lba_idx_bytes(partition_idx))[0]

    #

    def get_partition_attribute_flags_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[48:56]

    def get_partition_attribute_flags(self, partition_idx: int) -> int:
        return struct.unpack('<Q', self.get_partition_attribute_flags_bytes(partition_idx))[0]

    #

    def get_partition_name_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[56:128]

    def get_partition_name(self, partition_idx: int) -> str:
        return str(self.get_partition_name_bytes(partition_idx), encoding='utf-16le')

    # Top-level MBR fields
    def get_header_bytes(self) -> bytes:
        return self.primary_gpt_bytes[0:LBA_SIZE_BYTES]

    def get_signature_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[0:8]

    def get_signature(self) -> str:
        return str(self.get_signature_bytes(), encoding='ascii')

    #

    def get_revision_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[8:12]

    def get_revision(self) -> tuple:
        revision_tuple = struct.unpack('<HH', self.get_revision_bytes())
        return revision_tuple[1], revision_tuple[0]

    #

    def get_header_size_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[12:16]

    def get_header_size(self) -> int:
        return struct.unpack('<I', self.get_header_size_bytes())[0]

    #

    def get_crc_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[16:20]

    def get_crc(self) -> int:
        return struct.unpack('<I', self.get_crc_bytes())[0]

    #

    def get_reserved1_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[20:24]

    def get_reserved1(self) -> int:
        return struct.unpack('<I', self.get_reserved1_bytes())[0]
    #

    def get_current_lba_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[24:32]

    def get_current_lba(self) -> int:
        return struct.unpack('<Q', self.get_current_lba_bytes())[0]

    #

    def get_backup_lba_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[32:40]

    def get_backup_lba(self) -> int:
        return struct.unpack('<Q', self.get_backup_lba_bytes())[0]

    #

    def get_first_usable_lba_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[40:48]

    def get_first_usable_lba(self) -> int:
        return struct.unpack('<Q', self.get_first_usable_lba_bytes())[0]

    #

    def get_last_usable_lba_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[48:56]

    def get_last_usable_lba(self) -> int:
        return struct.unpack('<Q', self.get_last_usable_lba_bytes())[0]

    #

    def get_disk_guid_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[56:72]

    def get_disk_guid(self) -> bytes:
        return GPT.get_guid_str(self.get_disk_guid_bytes())

    #

    def get_starting_partition_lba_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[72:80]

    def get_starting_partition_lba(self) -> int:
        return struct.unpack('<Q', self.get_starting_partition_lba_bytes())[0]

    #

    def get_nb_partitions_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[80:84]

    def get_nb_partitions(self) -> int:
        return struct.unpack('<I', self.get_nb_partitions_bytes())[0]

    #

    def get_partition_size_lba_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[84:88]

    def get_partition_size_lba(self) -> int:
        return struct.unpack('<I', self.get_partition_size_lba_bytes())[0]

    #

    def get_crc_partitions_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[88:92]

    def get_crc_partitions(self) -> int:
        return struct.unpack('<I', self.get_crc_partitions_bytes())[0]

    #

    def get_reserved2_bytes(self) -> bytes:
        header_bytes = self.get_header_bytes()

        return header_bytes[92:LBA_SIZE_BYTES]

    #

    def read(self, block_device: str) -> None:
        self.block_device = block_device
        self.mbr_bytes = read_lba(block_device, 0, 1)
        self.primary_gpt_bytes = read_lba(block_device, 1, GPT_SIZE_LBA)
        self.backup_gpt_bytes = read_lba(block_device, -33, GPT_SIZE_LBA)

    @staticmethod
    def display_partition_attribute_flags(attributes: int) -> None:
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


    def display_partition(self, partition_idx: int) -> None:
        partition_type_guid_str = self.get_partition_type_guid(partition_idx)
        print("    Partition type GUID: %s [%s]" % (partition_type_guid_str, GPT.partition_type_description(partition_type_guid_str)))
        print("    Partition GUID: %s" % self.get_partition_unique_guid(partition_idx))
        print("    First LBA: %d" % self.get_partition_first_lba_idx(partition_idx))
        print("    Last LBA: %d" % self.get_partition_last_lba_idx(partition_idx))
        print("    Attribute flags: %d" % self.get_partition_attribute_flags(partition_idx))
        GPT.display_partition_attribute_flags(self.get_partition_attribute_flags(partition_idx))
        print("    Partition name: %s" % self.get_partition_name(partition_idx))

    def display(self):
        print("Signature: %s" % self.get_signature())
        print("Revision: %d.%d" % self.get_revision())
        print("Header size: %d" % self.get_header_size())
        print("CRC32: %d" % self.get_crc())
        print("Reserved: %d" % self.get_reserved1())
        print("Current LBA: %d" % self.get_current_lba())
        print("Backup LBA: %d" % self.get_backup_lba())
        print("First usable LBA for partitions: %d" % self.get_first_usable_lba())
        print("Last usable LBA for partitions: %d" % self.get_last_usable_lba())
        print("Disk GUID: %s" % self.get_disk_guid())
        print("Starting LBA of array of partition entries: %d" % self.get_starting_partition_lba())
        print("Number of partition entries in array: %d" % self.get_nb_partitions())
        print("Size (LBA) of a single partition entry: %d" % self.get_partition_size_lba())
        print("CRC32 of partition entries array: %d" % self.get_crc_partitions())
        print("Reserved: %s" % bytes_hexstr(self.get_reserved2_bytes()))

        for i in range(GPT_NB_PARTITION_ENTRIES):
            if self.get_partition_type_guid(i) != GPT_PARTITION_TYPE_GUID_UNUSED:
                print("Partition %d:" % i)
                self.display_partition(i)
