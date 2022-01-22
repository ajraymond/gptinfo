PARTITION_TYPE_GUIDs = {
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
		description = PARTITION_TYPE_GUIDs[guid.lower()]
	except KeyError:
		description = "Not documented"

	return description

