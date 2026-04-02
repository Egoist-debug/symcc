#pragma once

#include <isc/result.h>

#include <dns/dispatch.h>

isc_result_t
named_resolver_afl_symcc_orchestrator_start(const char *config);

void
named_resolver_afl_symcc_orchestrator_dispatchmgr_ready(dns_dispatchmgr_t *mgr);

void
named_resolver_afl_symcc_orchestrator_stop(void);
