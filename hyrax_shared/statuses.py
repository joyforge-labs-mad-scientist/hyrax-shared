"""The task-status vocabulary — single source of truth across all three services.

Before v0.3.0 these nine strings were assigned independently in the API, Main
and Webhook repos with no shared constant, so a tenth value could appear in one
service while the published OpenAPI enum and the other repos stayed silently
wrong (owner decision 26c8b875, 2026-08-18, executed 2026-08-20).

Rules for changing this vocabulary:

- ADDING a value is a customer-visible event: the API publishes TASK_STATUSES
  as a closed enum in /openapi.json, and the customer guide's section 10 table
  documents the set. Both must move in the same change, with a guide changelog
  entry — a strict generated client will reject an undeclared value.
- The tuple ORDER is part of the published contract (it is the enum order in
  /openapi.json). Append new values in lifecycle position; never reorder.
- Each service keeps writing its status literals at its own call sites; the
  per-repo sync tests bind those literals to this vocabulary.

Deliberately NOT here:

- "Task not found" — a row-absent sentinel from the API's data layer, never a
  task status; the API converts it to a 404.
- The scorecard's own `status` key (e.g. "Error") — a different field inside
  the results payload, described-tier, set by Main's scoring.
- "Unknown" — the API data layer's default for a corrupt row with no Status
  column; corruption-only, not part of the vocabulary.
"""

# Lifecycle order. This is the exact enum the API publishes in /openapi.json.
TASK_STATUSES = (
    "Queued",                                 # API, on submit
    "Processing",                             # Main, on queue pickup
    "Pending External Signals",               # Main, deferred providers owed
    "Completed",                              # Main / Webhook — success
    "Failed",                                 # Main — poison dead-letter / stale-Processing reaper
    "Processing Error",                       # Webhook — unexpected failure handling the result
    "Webhook Delivery Failed",                # Webhook — scorecard succeeded, delivery did not
    "Webhook Delivery Blocked (Security)",    # Webhook — delivery stopped for a security reason
    "Invalid Webhook URL",                    # Webhook — URL rejected before any attempt
)

NON_TERMINAL_STATUSES = TASK_STATUSES[:3]
TERMINAL_STATUSES = TASK_STATUSES[3:]
