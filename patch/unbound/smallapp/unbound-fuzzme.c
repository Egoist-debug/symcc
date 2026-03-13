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

	if (read_stdin(buffer, sizeof(buffer), &input_len) != 0) {
		return 1;
	}
	if (input_len == 0) {
		return 1;
	}

	return unbound_afl_symcc_run_case(buffer, input_len, &oracle);
}
