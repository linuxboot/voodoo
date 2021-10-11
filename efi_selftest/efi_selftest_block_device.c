// SPDX-License-Identifier: GPL-2.0+
/*
 * efi_selftest_block
 *
 * Copyright (c) 2017 Heinrich Schuchardt <xypron.glpk@gmx.de>
 *
 * This test checks the driver for block IO devices.
 * A disk image is created in memory.
 * A handle is created for the new block IO device.
 * The block I/O protocol is installed on the handle.
 * ConnectController is used to setup partitions and to install the simple
 * file protocol.
 * A known file is read from the file system and verified.
 */

#include <efi_selftest.h>
static struct efi_boot_services *boottime;
#if 0
static const efi_guid_t block_io_protocol_guid = BLOCK_IO_GUID;
static const efi_guid_t guid_device_path = DEVICE_PATH_GUID;
static const efi_guid_t guid_simple_file_system_protocol =
					EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static const efi_guid_t guid_file_system_info = EFI_FILE_SYSTEM_INFO_GUID;
static efi_guid_t guid_vendor =
	EFI_GUID(0xdbca4c98, 0x6cb0, 0x694d,
		 0x08, 0x72, 0x81, 0x9c, 0x65, 0x0c, 0xb7, 0xb8);

static struct efi_device_path *dp;
#endif
/* Handle for the block IO device */
static EFI_HANDLE disk_handle;

/*
 * Setup unit test.
 *
 * @handle:	handle of the loaded image
 * @systable:	system table
 * @return:	EFI_ST_SUCCESS for success
 */
static int setup(const efi_handle_t handle,
		 const struct efi_system_table *systable)
{
	return EFI_ST_SUCCESS;
}

/*
 * Tear down unit test.
 *
 * @return:	EFI_ST_SUCCESS for success
 */
static int teardown(void)
{
	EFI_STATUS r = EFI_ST_SUCCESS;
	return r;
}

/*
 * Get length of device path without end tag.
 *
 * @dp		device path
 * @return	length of device path in bytes
 */
static uint dp_size(struct efi_device_path *dp)
{
	struct efi_device_path *pos = dp;

	while (pos->type != DEVICE_PATH_TYPE_END)
		pos = (struct efi_device_path *)((char *)pos + pos->length);
	return (char *)pos - (char *)dp;
}

/*
 * Execute unit test.
 *
 * @return:	EFI_ST_SUCCESS for success
 */
static int execute(void)
{
	EFI_STATUS ret;
	size_t no_handles;
	uint i, len;
	EFI_HANDLE *handles;
	EFI_HANDLE handle_partition = NULL;
	struct efi_device_path *dp_partition;
	struct efi_simple_file_system_protocol *file_system;
	struct efi_file_handle *root, *file;
	struct {
		struct efi_file_system_info info;
		uint16_t label[12];
	} system_info;
	size_t buf_size;
	static char buf[16] __aligned(4096);

	/* Connect controller to virtual disk */
	ret = boottime->connect_controller(disk_handle, NULL, NULL, 1);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to connect controller\n");
		return EFI_ST_FAILURE;
	}

	/* Get the handle for the partition */
	ret = boottime->locate_handle_buffer(
				BY_PROTOCOL, &guid_device_path, NULL,
				&no_handles, &handles);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to locate handles\n");
		return EFI_ST_FAILURE;
	}
	len = dp_size(dp);
	for (i = 0; i < no_handles; ++i) {
		ret = boottime->open_protocol(handles[i], &guid_device_path,
					      (void **)&dp_partition,
					      NULL, NULL,
					      EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (ret != EFI_SUCCESS) {
			efi_st_error("Failed to open device path protocol\n");
			return EFI_ST_FAILURE;
		}
		if (len >= dp_size(dp_partition))
			continue;
		if (efi_st_memcmp(dp, dp_partition, len))
			continue;
		handle_partition = handles[i];
		break;
	}
	ret = boottime->free_pool(handles);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to free pool memory\n");
		return EFI_ST_FAILURE;
	}
	if (!handle_partition) {
		efi_st_error("Partition handle not found\n");
		return EFI_ST_FAILURE;
	}

	/* Open the simple file system protocol */
	ret = boottime->open_protocol(handle_partition,
				      &guid_simple_file_system_protocol,
				      (void **)&file_system, NULL, NULL,
				      EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to open simple file system protocol\n");
		return EFI_ST_FAILURE;
	}

	/* Open volume */
	ret = file_system->open_volume(file_system, &root);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to open volume\n");
		return EFI_ST_FAILURE;
	}
	buf_size = sizeof(system_info);
	ret = root->getinfo(root, &guid_file_system_info, &buf_size,
			    &system_info);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to get file system info\n");
		return EFI_ST_FAILURE;
	}
	if (system_info.info.block_size != 512) {
		efi_st_error("Wrong block size %u, expected 512\n",
			     system_info.info.block_size);
		return EFI_ST_FAILURE;
	}
	if (efi_st_strcmp_16_8(system_info.info.volume_label, "U-BOOT TEST")) {
		efi_st_todo(
			"Wrong volume label '%ps', expected 'U-BOOT TEST'\n",
			system_info.info.volume_label);
	}

	/* Read file */
	ret = root->open(root, &file, (int16_t *)L"hello.txt", EFI_FILE_MODE_READ,
			 0);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to open file\n");
		return EFI_ST_FAILURE;
	}
	buf_size = sizeof(buf) - 1;
	ret = file->read(file, &buf_size, buf);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to read file\n");
		return EFI_ST_FAILURE;
	}
	if (buf_size != 13) {
		efi_st_error("Wrong number of bytes read: %u\n",
			     (unsigned int)buf_size);
		return EFI_ST_FAILURE;
	}
	if (efi_st_memcmp(buf, "Hello world!", 12)) {
		efi_st_error("Unexpected file content\n");
		return EFI_ST_FAILURE;
	}
	ret = file->close(file);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to close file\n");
		return EFI_ST_FAILURE;
	}

#ifdef CONFIG_FAT_WRITE
	/* Write file */
	ret = root->open(root, &file, (s16 *)L"u-boot.txt", EFI_FILE_MODE_READ |
			 EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to open file\n");
		return EFI_ST_FAILURE;
	}
	buf_size = 7;
	boottime->set_mem(buf, sizeof(buf), 0);
	boottime->copy_mem(buf, "U-Boot", buf_size);
	ret = file->write(file, &buf_size, buf);
	if (ret != EFI_SUCCESS || buf_size != 7) {
		efi_st_error("Failed to write file\n");
		return EFI_ST_FAILURE;
	}
	ret = file->close(file);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to close file\n");
		return EFI_ST_FAILURE;
	}

	/* Verify file */
	boottime->set_mem(buf, sizeof(buf), 0);
	ret = root->open(root, &file, (s16 *)L"u-boot.txt", EFI_FILE_MODE_READ,
			 0);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to open file\n");
		return EFI_ST_FAILURE;
	}
	buf_size = sizeof(buf) - 1;
	ret = file->read(file, &buf_size, buf);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to read file\n");
		return EFI_ST_FAILURE;
	}
	if (buf_size != 7) {
		efi_st_error("Wrong number of bytes read: %u\n",
			     (unsigned int)buf_size);
		return EFI_ST_FAILURE;
	}
	if (efi_st_memcmp(buf, "U-Boot", 7)) {
		efi_st_error("Unexpected file content %s\n", buf);
		return EFI_ST_FAILURE;
	}
	ret = file->close(file);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to close file\n");
		return EFI_ST_FAILURE;
	}
#else
	efi_st_todo("CONFIG_FAT_WRITE is not set\n");
#endif /* CONFIG_FAT_WRITE */

	/* Close volume */
	ret = root->close(root);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Failed to close volume\n");
		return EFI_ST_FAILURE;
	}

	return EFI_ST_SUCCESS;
}

EFI_UNIT_TEST(blkdev) = {
	.name = "block device",
	.phase = EFI_EXECUTE_BEFORE_BOOTTIME_EXIT,
	.setup = setup,
	.execute = execute,
	.teardown = teardown,
};
