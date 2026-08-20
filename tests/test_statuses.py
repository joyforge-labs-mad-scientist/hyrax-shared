"""The vocabulary is a published contract: pin every string, byte for byte.

The exact-tuple test is deliberate duplication — a change to any status
string, to the count, or to the ORDER (which is the /openapi.json enum order)
must fail here and force the author through the customer-visible-change
checklist in the module docstring.
"""
from hyrax_shared.statuses import (
    NON_TERMINAL_STATUSES,
    TASK_STATUSES,
    TERMINAL_STATUSES,
)


def test_the_nine_values_exactly_in_order():
    assert TASK_STATUSES == (
        "Queued",
        "Processing",
        "Pending External Signals",
        "Completed",
        "Failed",
        "Processing Error",
        "Webhook Delivery Failed",
        "Webhook Delivery Blocked (Security)",
        "Invalid Webhook URL",
    )


def test_no_duplicates():
    assert len(set(TASK_STATUSES)) == len(TASK_STATUSES)


def test_subsets_partition_the_vocabulary():
    assert NON_TERMINAL_STATUSES + TERMINAL_STATUSES == TASK_STATUSES
    assert not set(NON_TERMINAL_STATUSES) & set(TERMINAL_STATUSES)


def test_non_terminal_is_the_waiting_set():
    assert NON_TERMINAL_STATUSES == ("Queued", "Processing", "Pending External Signals")


def test_sentinels_are_not_statuses():
    assert "Task not found" not in TASK_STATUSES
    assert "Unknown" not in TASK_STATUSES
    assert "Error" not in TASK_STATUSES
