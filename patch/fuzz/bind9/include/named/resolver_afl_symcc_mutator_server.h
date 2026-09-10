#pragma once

#include <inttypes.h>
#include <stddef.h>

#include <isc/buffer.h>
#include <isc/region.h>
#include <isc/result.h>

#include <dns/dispatch.h>

typedef struct named_resolver_afl_symcc_mutator_counters {
	uint64_t received;
	uint64_t replied;
	uint64_t parse_errors;
} named_resolver_afl_symcc_mutator_counters_t;

isc_result_t
named_resolver_afl_symcc_mutator_server_start(const char *config);

isc_result_t
named_resolver_afl_symcc_mutator_dispatch_hook(
	dns_dispentry_t *resp, const isc_region_t *request,
	unsigned char *response_buf, size_t response_buf_size,
	isc_region_t *response, void *arg);

void
named_resolver_afl_symcc_mutator_server_stop(void);

void
named_resolver_afl_symcc_mutator_server_add_received(uint64_t delta);

void
named_resolver_afl_symcc_mutator_server_add_replied(uint64_t delta);

void
named_resolver_afl_symcc_mutator_server_add_parse_errors(uint64_t delta);

void
named_resolver_afl_symcc_mutator_server_get_counters(
	named_resolver_afl_symcc_mutator_counters_t *counters);

void
named_resolver_afl_symcc_mutator_server_reset_response_sequence(void);

void
named_resolver_afl_symcc_mutator_server_set_responses(
	const uint8_t *const *responses, const size_t *response_lens,
	size_t response_count);

void
named_resolver_afl_symcc_mutator_server_clear_responses(void);

