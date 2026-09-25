"""A worker that finishes inside its deadline is never reported as timed out."""

from __future__ import annotations

from threading import Event, Lock

from shadowscan.engine import _JobState, _pending_expired


def state(deadline, completed_at):
    job = _JobState(cancelled=Event(), publication_lock=Lock())
    job.deadline = deadline
    job.completed_at = completed_at
    return job


def test_pending_future_that_completed_before_its_deadline_is_not_expired():
    assert _pending_expired(state(deadline=100.0, completed_at=99.9), now=100.04) is False


def test_pending_future_past_its_deadline_without_completion_is_expired():
    assert _pending_expired(state(deadline=100.0, completed_at=None), now=100.04) is True
    assert _pending_expired(state(deadline=100.0, completed_at=100.2), now=100.3) is True


def test_no_deadline_or_time_remaining_never_expires():
    assert _pending_expired(state(deadline=None, completed_at=None), now=1e9) is False
    assert _pending_expired(state(deadline=100.0, completed_at=None), now=99.0) is False
