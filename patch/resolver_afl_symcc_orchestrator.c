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

#include <stdio.h>
#include <stdlib.h>

#include <isc/result.h>

#include <named/resolver_afl_symcc_mutator_server.h>
#include <named/resolver_afl_symcc_orchestrator.h>

static int g_initialized = 0;

isc_result_t
named_resolver_afl_symcc_orchestrator_start(const char *config) {
	isc_result_t result;

	if (g_initialized) {
		return ISC_R_SUCCESS;
	}

	result = named_resolver_afl_symcc_mutator_server_start(config);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	g_initialized = 1;
	return ISC_R_SUCCESS;
}

void
named_resolver_afl_symcc_orchestrator_stop(void) {
	named_resolver_afl_symcc_mutator_counters_t counters;

	if (!g_initialized) {
		return;
	}

	named_resolver_afl_symcc_mutator_server_get_counters(&counters);

	fprintf(stderr,
		"[resolver-afl-symcc] Statistics:\n"
		"  Received: %" PRIu64 "\n"
		"  Replied: %" PRIu64 "\n"
		"  Parse errors: %" PRIu64 "\n",
		counters.received, counters.replied, counters.parse_errors);

	named_resolver_afl_symcc_mutator_server_stop();

	g_initialized = 0;
}
