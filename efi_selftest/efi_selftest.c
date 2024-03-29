// SPDX-License-Identifier: GPL-2.0+
/*
 * EFI efi_selftest
 *
 * Copyright (c) 2017 Heinrich Schuchardt <xypron.glpk@gmx.de>
 */

#include <efi_selftest.h>

/* Constants for test step bitmap */
#define EFI_ST_SETUP	1
#define EFI_ST_EXECUTE	2
#define EFI_ST_TEARDOWN	4

static const struct _EFI_SYSTEM_TABLE *systable;
struct efi_boot_services *boottime;
static const struct efi_runtime_services *runtime;
static EFI_HANDLE handle;
static uint16_t reset_message[] = L"Selftest completed";

/*
 * Exit the boot services.
 *
 * The size of the memory map is determined.
 * Pool memory is allocated to copy the memory map.
 * The memory map is copied and the map key is obtained.
 * The map key is used to exit the boot services.
 */
void efi_st_exit_boot_services(void)
{
	uint map_size = 0;
	uint map_key;
	uint desc_size;
	uint32_t desc_version;
	EFI_STATUS ret;
# ifdef TODO_TEST_MEMORY_ALLOCATION
	struct efi_mem_desc *memory_map;

	ret = boottime->get_memory_map(&map_size, NULL, &map_key, &desc_size,
				       &desc_version);
	if (ret != EFI_BUFFER_TOO_SMALL) {
		efi_st_error(
			"GetMemoryMap did not return EFI_BUFFER_TOO_SMALL\n");
		return;
	}
	/* Allocate extra space for newly allocated memory */
	map_size += sizeof(struct efi_mem_desc);
	ret = boottime->allocate_pool(EFI_BOOT_SERVICES_DATA, map_size,
				      (void **)&memory_map);
	if (ret != EFI_SUCCESS) {
		efi_st_error("AllocatePool did not return EFI_SUCCESS\n");
		return;
	}
	ret = boottime->get_memory_map(&map_size, memory_map, &map_key,
				       &desc_size, &desc_version);
	if (ret != EFI_SUCCESS) {
		efi_st_error("GetMemoryMap did not return EFI_SUCCESS\n");
		return;
	}
	ret = boottime->exit_boot_services(handle, map_key);
	if (ret != EFI_SUCCESS) {
		efi_st_error("ExitBootServices did not return EFI_SUCCESS\n");
		return;
	}
	Print(/*EFI_WHITE*/L "\nBoot services terminated\n");
#endif
	
}

/*
 * Set up a test.
 *
 * @test	the test to be executed
 * @failures	counter that will be incremented if a failure occurs
 * @return	EFI_ST_SUCCESS for success
 */
static int setup(struct efi_unit_test *test, unsigned int *failures)
{
	if (!test->setup) {
		test->setup_ok = EFI_ST_SUCCESS;
		return EFI_ST_SUCCESS;
	}
	Print(L"%B","\nSetting up '%s'\n", test->name);
	test->setup_ok = test->setup(handle, (const struct efi_system_table*)systable);
	if (test->setup_ok != EFI_ST_SUCCESS) {
		efi_st_error("Setting up '%s' failed\n", test->name);
		++*failures;
	} else {
		efi_st_printc(EFI_LIGHTGREEN,"Setting up '%s' succeeded\n", test->name);
	}
	return test->setup_ok;
}

/*
 * Execute a test.
 *
 * @test	the test to be executed
 * @failures	counter that will be incremented if a failure occurs
 * @return	EFI_ST_SUCCESS for success
 */
static int execute(struct efi_unit_test *test, unsigned int *failures)
{
	int ret;

	if (!test->execute)
		return EFI_ST_SUCCESS;
	Print(L"%B","\nExecuting '%s'\n", test->name);
	ret = test->execute();
	if (ret != EFI_ST_SUCCESS) {
		efi_st_error("Executing '%s' failed\n", test->name);
		++*failures;
	} else {
		efi_st_printc(EFI_LIGHTGREEN, "Executing '%s' succeeded\n", test->name);
	}
	return ret;
}

/*
 * Tear down a test.
 *
 * @test	the test to be torn down
 * @failures	counter that will be incremented if a failure occurs
 * @return	EFI_ST_SUCCESS for success
 */
static int teardown(struct efi_unit_test *test, unsigned int *failures)
{
	int ret;

	if (!test->teardown)
		return EFI_ST_SUCCESS;
	Print(L"%B","\nTearing down '%s'\n", test->name);
	ret = test->teardown();
	if (ret != EFI_ST_SUCCESS) {
		efi_st_error("Tearing down '%s' failed\n", test->name);
		++*failures;
	} else {
		efi_st_printc(EFI_LIGHTGREEN, "Tearing down '%s' succeeded\n", test->name);
	}
	return ret;
}

extern EFI_UNIT_TEST(rtc);
EFI_UNIT_TEST(blkdev);
struct efi_unit_test *tests[] = {
	&rtc,
	&blkdev,
};

enum {
	num_tests = sizeof(tests) / sizeof(tests[0])
};
/*
 * Check that a test exists.
 *
 * @testname:	name of the test
 * @return:	test, or NULL if not found
 */
static struct efi_unit_test *find_test(const uint16_t *testname)
{
	struct efi_unit_test *test;

	for(int i = 0; i < num_tests; i++) {
		test = tests[i];
		if (!efi_st_strcmp_16_8(testname, test->name))
			return test;
	}
	Print(L"\nTest '%ps' not found\n", testname);
	return NULL;
}

/*
 * List all available tests.
 */
static void list_all_tests(void)
{
	struct efi_unit_test *test;

	/* List all tests */
	Print(L"\nAvailable tests:\n");
	for(int i = 0; i < num_tests; i++) {
		test = tests[i];
		Print(L"'%s'%s\n", test->name,
			      test->on_request ? " - on request" : "");
	}
}

/*
 * Execute test steps of one phase.
 *
 * @testname	name of a single selected test or NULL
 * @phase	test phase
 * @steps	steps to execute (mask with bits from EFI_ST_...)
 * failures	returns EFI_ST_SUCCESS if all test steps succeeded
 */
void efi_st_do_tests(const uint16_t *testname, unsigned int phase,
		     unsigned int steps, unsigned int *failures)
{
	struct efi_unit_test *test;

	for(int i = 0; i < num_tests; i++) {
		test = tests[i];
		if (testname ?
		    efi_st_strcmp_16_8(testname, test->name) : test->on_request)
			continue;
		if (test->phase != phase)
			continue;
		if (steps & EFI_ST_SETUP)
			setup(test, failures);
		if (steps & EFI_ST_EXECUTE && test->setup_ok == EFI_ST_SUCCESS)
			execute(test, failures);
		if (steps & EFI_ST_TEARDOWN)
			teardown(test, failures);
	}
}

/*
 * Execute selftest of the EFI API
 *
 * This is the main entry point of the EFI selftest application.
 *
 * All tests use a driver model and are run in three phases:
 * setup, execute, teardown.
 *
 * A test may be setup and executed at boottime,
 * it may be setup at boottime and executed at runtime,
 * or it may be setup and executed at runtime.
 *
 * After executing all tests the system is reset.
 *
 * @image_handle:	handle of the loaded EFI image
 * @systab:		EFI system table
 */
EFI_STATUS EFIAPI efi_selftest(EFI_HANDLE image_handle,
				 EFI_SYSTEM_TABLE *systab)
{
	unsigned int failures = 0;
	const uint16_t *testname = NULL;
	struct efi_loaded_image *loaded_image;
	EFI_STATUS ret;
	const efi_guid_t efi_guid_loaded_image = LOADED_IMAGE_GUID;
	systable = systab;
	boottime = ((struct efi_system_table *)systable)->boottime;
	runtime = ((struct efi_system_table *)systable)->runtime;
	handle = image_handle;
	con_out = ((struct efi_system_table *)systable)->con_out;
	con_in = ((struct efi_system_table *)systable)->con_in;

	Print(L"r %x co %x ci %x\n", runtime, con_out, con_in);
	Print(L"first call to efi_st_error follows...\n");
	efi_st_error("Test message from selftest\n");
	Print(L"if you can read this, it's ok\n");
	ret = boottime->handle_protocol(image_handle, &efi_guid_loaded_image,
					(void **)&loaded_image);
	if (ret != EFI_SUCCESS) {
		efi_st_error("Cannot open loaded image protocol\n");
		return ret;
	}

	Print(L"ret %x\n", ret);
	if (loaded_image->load_options)
		testname = (uint16_t *)loaded_image->load_options;
	Print(L"testname %x\n", testname);
	testname = 0;

	if (testname) {
		if (!efi_st_strcmp_16_8(testname, "list") ||
		    !find_test(testname)) {
			list_all_tests();
			/*
			 * TODO:
			 * Once the Exit boottime service is correctly
			 * implemented we should call
			 *   boottime->exit(image_handle, EFI_SUCCESS, 0, NULL);
			 * here, cf.
			 * https://lists.denx.de/pipermail/u-boot/2017-October/308720.html
			 */
			return EFI_SUCCESS;
		}
	}

	Print(/*EFI_WHITE*/L"\nTesting EFI API implementation\n");

	if (testname)
		Print(/*EFI_WHITE*/L"\nSelected test: '%ps'\n", testname);
	else
		Print(/*EFI_WHITE*/L"\nNumber of tests to execute: %u\n",num_tests);

	/* Execute boottime tests */
	efi_st_do_tests(testname, EFI_EXECUTE_BEFORE_BOOTTIME_EXIT,
			EFI_ST_SETUP | EFI_ST_EXECUTE | EFI_ST_TEARDOWN,
			&failures);

	/* Execute mixed tests */
	efi_st_do_tests(testname, EFI_SETUP_BEFORE_BOOTTIME_EXIT,
			EFI_ST_SETUP, &failures);

	efi_st_exit_boot_services();

	efi_st_do_tests(testname, EFI_SETUP_BEFORE_BOOTTIME_EXIT,
			EFI_ST_EXECUTE | EFI_ST_TEARDOWN, &failures);

	/* Execute runtime tests */
	efi_st_do_tests(testname, EFI_SETUP_AFTER_BOOTTIME_EXIT,
			EFI_ST_SETUP | EFI_ST_EXECUTE | EFI_ST_TEARDOWN,
			&failures);

	/* Give feedback */
	Print(/*EFI_WHITE*/L"\nSummary: %u failures\n\n", failures);

	/* Reset system */
	Print(L"Preparing for reset. Press any key...\n");
	efi_st_get_key();
	runtime->reset_system(EFI_RESET_WARM, EFI_NOT_READY,
			      sizeof(reset_message), reset_message);
	Print(L"\n");
	efi_st_error("Reset failed\n");

	return EFI_UNSUPPORTED;
}
