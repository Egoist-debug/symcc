#pragma once

#include <stdbool.h>
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
