#pragma once

#include <isc/result.h>

isc_result_t
named_resolver_afl_symcc_orchestrator_start(const char *config);

void
named_resolver_afl_symcc_orchestrator_stop(void);
