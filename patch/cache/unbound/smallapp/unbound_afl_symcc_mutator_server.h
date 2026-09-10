#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct unbound_afl_symcc_mutator_stats {
	uint64_t received;
	uint64_t replied;
	uint64_t parse_errors;
} unbound_afl_symcc_mutator_stats_t;

bool
unbound_afl_symcc_mutator_server_start(uint16_t requested_port,
	uint16_t *bound_port);

void
unbound_afl_symcc_mutator_server_stop(void);

bool
unbound_afl_symcc_mutator_server_get_stats(unbound_afl_symcc_mutator_stats_t *out);

void
unbound_afl_symcc_mutator_server_set_responses(
	const uint8_t *const *responses, const size_t *response_lens,
	size_t response_count);

void
unbound_afl_symcc_mutator_server_clear_responses(void);

void
unbound_afl_symcc_mutator_server_reset_response_sequence(void);

