/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <isc/managers.h>
#include <isc/rwlock.h>
#include <isc/util.h>
#include <isc/uv.h>

typedef struct {
	isc_mem_t *mctx;
	bool destroy_mctx;
} isc_manager_mctx_record_t;

static isc_manager_mctx_record_t isc_manager_mctx_records[32];

static void
record_manager_mctx(isc_mem_t *mctx, bool destroy_mctx) {
	size_t free_slot = 0;
	bool have_free_slot = false;

	for (size_t i = 0; i < ARRAY_SIZE(isc_manager_mctx_records); ++i) {
		if (isc_manager_mctx_records[i].mctx == mctx) {
			isc_manager_mctx_records[i].destroy_mctx = destroy_mctx;
			return;
		}
		if (!have_free_slot && isc_manager_mctx_records[i].mctx == NULL) {
			free_slot = i;
			have_free_slot = true;
		}
	}

	REQUIRE(have_free_slot);
	isc_manager_mctx_records[free_slot].mctx = mctx;
	isc_manager_mctx_records[free_slot].destroy_mctx = destroy_mctx;
}

static bool
take_manager_mctx_destroy_flag(isc_mem_t *mctx) {
	for (size_t i = 0; i < ARRAY_SIZE(isc_manager_mctx_records); ++i) {
		if (isc_manager_mctx_records[i].mctx != mctx) {
			continue;
		}
		const bool destroy_mctx = isc_manager_mctx_records[i].destroy_mctx;
		isc_manager_mctx_records[i].mctx = NULL;
		isc_manager_mctx_records[i].destroy_mctx = false;
		return destroy_mctx;
	}

	return false;
}

void
isc_managers_create(isc_mem_t **mctxp, uint32_t workers,
		    isc_loopmgr_t **loopmgrp, isc_nm_t **netmgrp) {
	bool destroy_mctx = false;

	REQUIRE(mctxp != NULL);
	if (*mctxp == NULL) {
		isc_mem_create(mctxp);
		INSIST(*mctxp != NULL);
		isc_mem_setname(*mctxp, "managers");
		destroy_mctx = true;
	}

	REQUIRE(loopmgrp != NULL && *loopmgrp == NULL);
	isc_loopmgr_create(*mctxp, workers, loopmgrp);
	INSIST(*loopmgrp != NULL);

	REQUIRE(netmgrp != NULL && *netmgrp == NULL);
	isc_netmgr_create(*mctxp, *loopmgrp, netmgrp);
	INSIST(*netmgrp != NULL);

	record_manager_mctx(*mctxp, destroy_mctx);
	isc_rwlock_setworkers(workers);
}

void
isc_managers_destroy(isc_mem_t **mctxp, isc_loopmgr_t **loopmgrp,
		     isc_nm_t **netmgrp) {
	bool destroy_mctx = false;

	REQUIRE(mctxp != NULL && *mctxp != NULL);
	REQUIRE(loopmgrp != NULL && *loopmgrp != NULL);
	REQUIRE(netmgrp != NULL && *netmgrp != NULL);
	destroy_mctx = take_manager_mctx_destroy_flag(*mctxp);

	/*
	 * The sequence of operations here is important:
	 */

	isc_netmgr_destroy(netmgrp);
	isc_loopmgr_destroy(loopmgrp);
	if (destroy_mctx) {
		isc_mem_destroy(mctxp);
	}
}
