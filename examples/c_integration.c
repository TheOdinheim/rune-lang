/*
 * Example: Using the RUNE C API directly.
 *
 * This demonstrates the complete lifecycle for evaluating RUNE governance
 * policies from C (or any language with C FFI support).
 *
 * Compile with:
 *   gcc -o example c_integration.c -lrune_lang -L/path/to/librune_lang.so
 *
 * Note: This is a documentation example showing the fail-closed pattern.
 */

#include <stdio.h>
#include <string.h>
#include "../tools/rune.h"

int main(void) {
    /* ── 1. Define a RUNE policy ────────────────────────────────── */
    const char *source =
        "policy AccessControl {\n"
        "    rule check_risk(subject_id: Int, action: Int, "
        "resource_id: Int, risk_score: Int) -> PolicyDecision {\n"
        "        if risk_score > 80 {\n"
        "            deny\n"
        "        } else {\n"
        "            permit\n"
        "        }\n"
        "    }\n"
        "}\n";

    /* ── 2. Load the policy module ──────────────────────────────── */
    const char *key = "my-signing-key";
    const char *name = "example";

    RuneModule *module = rune_module_load_source(
        source, strlen(source),
        (const uint8_t *)key, strlen(key),
        name, strlen(name)
    );

    if (module == NULL) {
        fprintf(stderr, "Failed to load RUNE module\n");
        return 1;
    }

    /* ── 3. Build a request ─────────────────────────────────────── */
    RunePolicyRequest request = {
        .subject_id = 42,
        .action = 1,
        .resource_id = 100,
        .risk_score = 85,
        .context_json = NULL,
        .context_json_len = 0
    };

    /* ── 4. Evaluate — decision is always written (fail-closed) ── */
    RunePolicyDecision decision;
    int32_t rc = rune_evaluate(module, &request, &decision);

    if (rc != 0) {
        fprintf(stderr, "Evaluation error: %s\n", decision.error_message);
        /* decision.outcome is RUNE_DENY on error — fail-closed */
    }

    switch (decision.outcome) {
        case RUNE_PERMIT:
            printf("Access granted\n");
            break;
        case RUNE_DENY:
            printf("Access denied\n");
            break;
        case RUNE_ESCALATE:
            printf("Needs human review\n");
            break;
        case RUNE_QUARANTINE:
            printf("Quarantined for investigation\n");
            break;
        default:
            printf("Error: %s\n", decision.error_message);
            break;
    }

    /* ── 5. Check audit trail ───────────────────────────────────── */
    printf("Audit records: %lu\n", (unsigned long)rune_audit_trail_len(module));

    /* ── 6. Clean up ────────────────────────────────────────────── */
    rune_module_free(module);

    /* Safe to call with NULL — no-op */
    rune_module_free(NULL);

    return 0;
}
