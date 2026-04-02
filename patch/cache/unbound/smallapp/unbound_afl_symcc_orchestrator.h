#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct unbound_afl_symcc_oracle {
	bool parse_ok;
	bool resolver_fetch_started;
	bool response_accepted;
	bool second_query_hit;
	bool cache_entry_created;
	bool timeout;
} unbound_afl_symcc_oracle_t;

void
unbound_afl_symcc_oracle_set_active(unbound_afl_symcc_oracle_t *oracle);

void
unbound_afl_symcc_oracle_clear_active(void);

void
unbound_afl_symcc_oracle_note_fetch_started(void);

void
unbound_afl_symcc_oracle_note_timeout(void);

int
unbound_afl_symcc_run_case(const uint8_t *input, size_t input_len,
	unbound_afl_symcc_oracle_t *oracle);

int
unbound_afl_symcc_dump_empty_cache(void);
