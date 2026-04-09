/*
 * RUNE Embedding API — C Header
 *
 * C-compatible interface for loading and evaluating RUNE policy modules.
 * Any language with C FFI support can use this API.
 *
 * GOVERNANCE CONSTRAINT: Every failure mode defaults to DENY. There is no
 * code path through this API that returns an implicit PERMIT due to an
 * internal failure.
 *
 * THREAD SAFETY: A RuneModule is NOT thread-safe. Each thread should load
 * its own module instance.
 *
 * MEMORY: The caller must call rune_module_free() to release loaded modules.
 * The caller must check for NULL returns from load functions.
 */

#ifndef RUNE_H
#define RUNE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Outcome constants ──────────────────────────────────────────── */

#define RUNE_PERMIT      0
#define RUNE_DENY        1
#define RUNE_ESCALATE    2
#define RUNE_QUARANTINE  3
#define RUNE_ERROR      (-1)

/* ── Types ──────────────────────────────────────────────────────── */

/**
 * Opaque handle for a loaded RUNE policy module.
 * Created by rune_module_load_source or rune_module_load_wasm.
 * Must be freed with rune_module_free.
 */
typedef struct RuneModule RuneModule;

/**
 * Policy evaluation request.
 * Matches the standard evaluate(subject_id, action, resource_id, risk_score)
 * signature. context_json is optional (NULL if not needed).
 */
typedef struct {
    int64_t  subject_id;
    int64_t  action;
    int64_t  resource_id;
    int64_t  risk_score;
    const char *context_json;
    size_t   context_json_len;
} RunePolicyRequest;

/**
 * Policy evaluation decision.
 * outcome is one of RUNE_PERMIT, RUNE_DENY, RUNE_ESCALATE,
 * RUNE_QUARANTINE, or RUNE_ERROR.
 *
 * On error, outcome is RUNE_ERROR and error_message is populated.
 * On evaluation failure, outcome is RUNE_DENY (fail-closed).
 */
typedef struct {
    int32_t  outcome;
    char     matched_rule[256];
    uint64_t evaluation_duration_us;
    char     error_message[512];
    uint64_t audit_record_id;
} RunePolicyDecision;

/* ── Lifecycle functions ────────────────────────────────────────── */

/**
 * Load a RUNE policy module from source code.
 *
 * Compiles the source through the full pipeline (lex -> parse ->
 * type check -> IR -> codegen -> WASM) and wraps it in an audited
 * evaluator.
 *
 * @param source         RUNE source code (UTF-8, not null-terminated)
 * @param source_len     Length of the source string in bytes
 * @param signing_key    Key for the cryptographic audit trail
 * @param signing_key_len Length of the signing key
 * @param module_name    Human-readable module name (UTF-8)
 * @param module_name_len Length of the module name
 * @return Opaque module handle, or NULL on failure.
 */
RuneModule *rune_module_load_source(
    const char *source,
    size_t source_len,
    const uint8_t *signing_key,
    size_t signing_key_len,
    const char *module_name,
    size_t module_name_len
);

/**
 * Load a RUNE policy module from pre-compiled WASM bytes.
 *
 * @param wasm_bytes     Compiled WASM module bytes
 * @param wasm_len       Length of the WASM bytes
 * @param signing_key    Key for the cryptographic audit trail
 * @param signing_key_len Length of the signing key
 * @param module_name    Human-readable module name (UTF-8)
 * @param module_name_len Length of the module name
 * @return Opaque module handle, or NULL on failure.
 */
RuneModule *rune_module_load_wasm(
    const uint8_t *wasm_bytes,
    size_t wasm_len,
    const uint8_t *signing_key,
    size_t signing_key_len,
    const char *module_name,
    size_t module_name_len
);

/**
 * Evaluate a policy request against a loaded module.
 *
 * The decision is always written to the output pointer, even on error.
 * FAIL-CLOSED: any error produces DENY, never PERMIT.
 *
 * @param module   Module handle from a load function (must not be NULL)
 * @param request  Pointer to the request struct (must not be NULL)
 * @param decision Pointer to the decision output struct (must not be NULL)
 * @return 0 on success, -1 on error.
 */
int32_t rune_evaluate(
    RuneModule *module,
    const RunePolicyRequest *request,
    RunePolicyDecision *decision
);

/**
 * Free a loaded module handle.
 *
 * Safe to call with NULL (no-op). After calling this, the module
 * pointer is invalid and must not be used.
 *
 * @param module Module handle to free, or NULL.
 */
void rune_module_free(RuneModule *module);

/**
 * Evaluate a policy request using the wire format (FlatBuffers-compatible).
 *
 * Takes serialized request bytes, evaluates the policy, and writes the
 * serialized decision to the output buffer.
 *
 * FAIL-CLOSED: deserialization failure produces a serialized DENY decision.
 *
 * @param module          Module handle (must not be NULL)
 * @param request_bytes   Serialized PolicyRequest bytes
 * @param request_len     Length of the request bytes
 * @param decision_buf    Output buffer for the serialized PolicyDecision
 * @param decision_buf_len Size of the output buffer
 * @param decision_written Number of bytes written to the output buffer
 * @return 0 on success, -1 on error, -2 if output buffer too small.
 */
int32_t rune_evaluate_wire(
    RuneModule *module,
    const uint8_t *request_bytes,
    size_t request_len,
    uint8_t *decision_buf,
    size_t decision_buf_len,
    size_t *decision_written
);

/**
 * Get the number of audit records in the module's trail.
 *
 * @param module Module handle (returns 0 if NULL).
 * @return Number of audit records.
 */
uint64_t rune_audit_trail_len(RuneModule *module);

/**
 * Get the last error message from the module.
 *
 * Returns a pointer to a null-terminated string, valid until the next
 * rune_evaluate call. Returns NULL if no error or module is NULL.
 *
 * @param module Module handle.
 * @return Error message or NULL.
 */
const char *rune_last_error(RuneModule *module);

#ifdef __cplusplus
}
#endif

#endif /* RUNE_H */
