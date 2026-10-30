/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Ttiouan Christophe
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <xen-arm/shm.h>

#include <uk/config.h>
#include <uk/essentials.h>
#include <uk/paging.h>
#include <uk/test.h>

#define TEST_SHM_ID	"uktest-shm"
#define TEST_SHM_VAL	0x0123456789abcdefUL

/**
 * Tests that a value written to a shm region mapped RW can be read back
 */
UK_TESTCASE(xen_static_shm, test_shm_write_read)
{
	volatile unsigned long *p;

	p = uk_shm_map(TEST_SHM_ID, UK_PAGING_PAGE_SIZE, UK_SHM_RW, 0);
	UK_TEST_EXPECT_NOT_NULL(p);
	if (unlikely(!p))
		return;

	*p = TEST_SHM_VAL;
	UK_TEST_EXPECT_SNUM_EQ(*p, TEST_SHM_VAL);
}

uk_testsuite_register(xen_static_shm, NULL);
