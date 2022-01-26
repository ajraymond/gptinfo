import struct
from enum import Enum

from lba import read_lba, LBA_SIZE_BYTES
from bytehelpers import bytes_hexstr
from debug import DEBUG, DEBUG_BYTES

MBR_NB_PRIMARY_PARTITIONS = 4

# https://en.wikipedia.org/wiki/Partition_type#List_of_partition_IDs
MBR_PARTITION_TYPE_GPT_PROTECTIVE = 0xee

MBR_PARTITION_TYPES = {
        0x00: "Unused entry",
        0x05: "Extended",
        0x07: "HPFS/NTFS/exFAT",
        0x0b: "W95 FAT32",
        0x0c: "W95 FAT32 (LBA)",
        0x0e: "W95 FAT16 (LBA)",
        0x0f: "W95 Extended (LBA)",
        0x82: "Linux swap / Solaris",
        0x83: "Linux",
        0x85: "Linux extended",
        0x86: "NTFS volume set",
        0x87: "NTFS volume set",
        0x88: "Linux plaintext",
        0x8e: "Linux LVM",
        0xee: "GPT Protective MBR",
}


class MBR:
    def __init__(self):
        self.block_device = None
        self.mbr_bytes = bytes(LBA_SIZE_BYTES)

    @staticmethod
    def partition_type_description(partition_type: int) -> str:
        try:
            description = MBR_PARTITION_TYPES[partition_type]
        except KeyError:
            description = "Not documented"

        return description

    def _parse_chs(self, chs_bytes: bytes) -> tuple:
        head = chs_bytes[0]
        sector = chs_bytes[1] & 0x3F
        cylinder = ((chs_bytes[1] & 0xC) << 2) | chs_bytes[2]

        return head, sector, cylinder

    # Partition-level fields
    def get_partition_status_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[0:1]

    def get_partition_status(self, partition_idx: int) -> int:
        return struct.unpack('<B', self.get_partition_status_bytes(partition_idx))[0]

    #

    def get_partition_first_absolute_sector_chs_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[1:4]

    def get_partition_first_absolute_sector_chs(self, partition_idx: int) -> tuple:
        return self._parse_chs(self.get_partition_first_absolute_sector_chs_bytes(partition_idx))

    #

    def get_partition_type_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[4:5]

    def get_partition_type(self, partition_idx: int) -> int:
        return struct.unpack('<B', self.get_partition_type_bytes(partition_idx))[0]

    #

    def get_partition_last_absolute_sector_chs_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[5:8]

    def get_partition_last_absolute_sector_chs(self, partition_idx: int) -> tuple:
        return self._parse_chs(self.get_partition_last_absolute_sector_chs_bytes(partition_idx))

    #

    def get_partition_first_absolute_sector_lba_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[8:12]

    def get_partition_first_absolute_sector_lba(self, partition_idx: int) -> int:
        return struct.unpack('<I', self.get_partition_first_absolute_sector_lba_bytes(partition_idx))[0]

    #

    def get_partition_nb_sectors_bytes(self, partition_idx: int) -> bytes:
        entry_bytes = self.get_partition_bytes(partition_idx)

        return entry_bytes[12:16]

    def get_partition_nb_sectors(self, partition_idx: int) -> int:
        return struct.unpack('<I', self.get_partition_nb_sectors_bytes(partition_idx))[0]

    # Top-level MBR fields
    def get_bootstrap_code_1_bytes(self) -> bytes:
        return self.mbr_bytes[0:218]

    #

    def get_disk_timestamp_bytes(self) -> bytes:
        return self.mbr_bytes[218:224]

    def get_disk_timestamp(self) -> tuple:
        b = self.get_disk_timestamp_bytes()

        zeros = struct.unpack('<H', b[0:2])[0]
        original_physical_drive = b[2]
        seconds = b[3]
        minutes = b[4]
        hours = b[5]

        return zeros, original_physical_drive, seconds, minutes, hours

    #

    def get_bootstrap_code_2_bytes(self, extended: bool = False) -> bytes:
        if extended:
            size = 222
        else:
            size = 216

        return self.mbr_bytes[224:224+size]

    #

    def get_bootstrap_code_bytes(self, extended: bool = False) -> bytes:
        return self.get_bootstrap_code_1_bytes() + self.get_bootstrap_code_2_bytes(extended)

    #

    def get_disk_signature_bytes(self) -> bytes:
        return self.mbr_bytes[440:446]

    def get_disk_signature(self) -> tuple:
        b = self.get_disk_signature_bytes()

        signature = struct.unpack('<I', b[0:4])[0]
        copy_protected = struct.unpack('<H', b[4:6])[0]

        return signature, copy_protected

    #

    def get_partition_bytes(self, partition_idx: int) -> bytes:
        if not (0 <= partition_idx <= 3):
            raise ValueError("Invalid partition index (%d)" % partition_idx)

        start_addr = 446 + partition_idx*16
        return self.mbr_bytes[start_addr:start_addr+16]

    #

    def get_boot_signature_bytes(self) -> bytes:
        return self.mbr_bytes[510:512]

    def get_boot_signature(self) -> int:
        return struct.unpack('<H', self.get_boot_signature_bytes())[0]

    #

    def read(self, block_device: str) -> None:
        self.block_device = block_device
        self.mbr_bytes = read_lba(block_device, 0)

    def display_partition(self, partition_idx: int) -> None:
        print("    Status: 0x%.2x" % self.get_partition_status(partition_idx))
        print("    First absolute sector address (CHS): %s" % str(self.get_partition_first_absolute_sector_chs(partition_idx)))
        partition_type = self.get_partition_type(partition_idx)
        print("    Partition type: 0x%.2x (%s)" % (partition_type, MBR.partition_type_description(partition_type)))
        print("    Last absolute sector (CHS): %s" % str(self.get_partition_last_absolute_sector_chs(partition_idx)))
        print("    First absolute sector (LBA): %d" % self.get_partition_first_absolute_sector_lba(partition_idx))
        print("    Nb sectors: %d" % self.get_partition_nb_sectors(partition_idx))

    def display(self):
        print("Bootstrap code:")
        print(bytes_hexstr(self.get_bootstrap_code_bytes()))
        print("Disk timestamp: zeros=%d original_physical_drive=0x%.2x seconds=%d minutes=%d hours=%d" % self.get_disk_timestamp())
        print("Disk signature: signature=%d protection=0x%.4x" % self.get_disk_signature())
        for i in range(MBR_NB_PRIMARY_PARTITIONS):
            print("Partition %d:" % i)
            self.display_partition(i)
        print("Boot signature: 0x%.4x" % self.get_boot_signature())

