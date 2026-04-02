#include "config.h"

#include "smallapp/unbound_afl_symcc_orchestrator.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define UNBOUND_AFL_SYMCC_MAX_INPUT 65536

static int
read_stdin(uint8_t *buffer, size_t capacity, size_t *input_len)
{
	size_t n_read = fread(buffer, 1, capacity, stdin);

	if (n_read == capacity) {
		fprintf(stderr, "input too big\n");
		return 1;
	}
	*input_len = n_read;
	return 0;
}

int
main(void)
{
	uint8_t buffer[UNBOUND_AFL_SYMCC_MAX_INPUT];
	size_t input_len = 0;
	unbound_afl_symcc_oracle_t oracle;
	const char *debug = getenv("UNBOUND_RESOLVER_AFL_SYMCC_DEBUG");

	if (read_stdin(buffer, sizeof(buffer), &input_len) != 0) {
		return 1;
	}
	if (input_len == 0) {
		if (getenv("UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH") != NULL) {
			return unbound_afl_symcc_dump_empty_cache();
		}
		return 1;
	}
	if (debug != NULL && strcmp(debug, "0") != 0) {
		fprintf(stderr,
			"[unbound-afl-symcc][debug] main len=%zu head=%02x%02x%02x%02x\n",
			input_len,
			input_len > 0 ? buffer[0] : 0,
			input_len > 1 ? buffer[1] : 0,
			input_len > 2 ? buffer[2] : 0,
			input_len > 3 ? buffer[3] : 0);
	}

	return unbound_afl_symcc_run_case(buffer, input_len, &oracle);
}
