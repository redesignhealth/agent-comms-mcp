"""Tests for the board's typed message schemas (schemas.py)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from schemas import (
    MAX_ACCEPTED_TYPES,
    MESSAGE_TYPES,
    AvailabilityRequestV1,
    AvailabilityResponseV1,
    ConfirmV1,
    CounterProposalV1,
    DeclineV1,
    NeedsClarificationV1,
    NoteV1,
    PayloadValidationError,
    TaskAssignV1,
    TaskCancelV1,
    TaskCompleteV1,
    TaskDeclineV1,
    TaskReportV1,
    get_schema,
    is_boundary_safe,
    validate_payload,
)

_NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(hours=2)
_NAIVE = datetime(2026, 8, 11, 12, 0)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def test_message_types_fits_within_max_accepted_types() -> None:
    """sorted(MESSAGE_TYPES) is used as _register's default accepted_types
    in test_service.py/test_comms_tools.py -- if the registry ever grows
    past MAX_ACCEPTED_TYPES, that default becomes invalid and either the
    default must be sliced or MAX_ACCEPTED_TYPES raised. A collected test
    (not a module-level assert, which silently vanishes under python -O)
    catches that regardless of which test module runs first."""
    assert len(MESSAGE_TYPES) <= MAX_ACCEPTED_TYPES


class TestAvailabilityRequest:
    def _valid(self, **overrides: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "window": {"start": _iso(_NOW), "end": _iso(_LATER)},
            "duration_min": 30,
            "modality": "video",
            "priority": "normal",
            "constraints": ["mornings_only"],
        }
        payload.update(overrides)
        return payload

    def test_accepts_valid_payload(self) -> None:
        model = AvailabilityRequestV1.model_validate(self._valid())
        assert model.type == "availability_request"
        assert model.duration_min == 30

    def test_accepts_minimal_constraints(self) -> None:
        model = AvailabilityRequestV1.model_validate(self._valid(constraints=[]))
        assert model.constraints == []

    def test_rejects_naive_window_start(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(
                self._valid(window={"start": _NAIVE.isoformat(), "end": _iso(_LATER)})
            )

    def test_rejects_naive_window_end(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(
                self._valid(window={"start": _iso(_NOW), "end": _NAIVE.isoformat()})
            )

    def test_rejects_window_start_after_end(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(
                self._valid(window={"start": _iso(_LATER), "end": _iso(_NOW)})
            )

    def test_rejects_window_start_equal_end(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(
                self._valid(window={"start": _iso(_NOW), "end": _iso(_NOW)})
            )

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(self._valid(free_text="please help"))

    @pytest.mark.parametrize("duration_min", [4, 481, 0, -5])
    def test_rejects_out_of_range_duration(self, duration_min: int) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(self._valid(duration_min=duration_min))

    @pytest.mark.parametrize("duration_min", [5, 480, 30])
    def test_accepts_boundary_duration(self, duration_min: int) -> None:
        AvailabilityRequestV1.model_validate(self._valid(duration_min=duration_min))

    def test_rejects_bad_modality(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(self._valid(modality="carrier_pigeon"))

    def test_rejects_bad_priority(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(self._valid(priority="urgent"))

    def test_rejects_bad_constraint_value(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(self._valid(constraints=["no_mondays"]))

    def test_rejects_too_many_constraints(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(self._valid(constraints=["mornings_only"] * 11))

    def test_rejects_duplicate_constraints(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(
                self._valid(constraints=["mornings_only", "mornings_only"])
            )

    def test_rejects_mismatched_type_discriminator(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityRequestV1.model_validate(self._valid(type="confirm"))

    def test_type_discriminator_defaults(self) -> None:
        payload = self._valid()
        assert "type" not in payload
        model = AvailabilityRequestV1.model_validate(payload)
        assert model.type == "availability_request"


class TestSlotShape:
    def _slot(self, **overrides: object) -> dict[str, object]:
        slot: dict[str, object] = {
            "start": _iso(_NOW),
            "end": _iso(_LATER),
            "preference": 0.5,
        }
        slot.update(overrides)
        return slot

    @pytest.mark.parametrize("preference", [-0.1, 1.1, -1.0, 2.0])
    def test_rejects_out_of_range_preference(self, preference: float) -> None:
        with pytest.raises(ValidationError):
            CounterProposalV1.model_validate({"slots": [self._slot(preference=preference)]})

    @pytest.mark.parametrize("preference", [0.0, 1.0, 0.5])
    def test_accepts_boundary_preference(self, preference: float) -> None:
        CounterProposalV1.model_validate({"slots": [self._slot(preference=preference)]})

    def test_rejects_naive_slot_datetime(self) -> None:
        with pytest.raises(ValidationError):
            CounterProposalV1.model_validate({"slots": [self._slot(start=_NAIVE.isoformat())]})

    def test_rejects_start_after_end(self) -> None:
        with pytest.raises(ValidationError):
            CounterProposalV1.model_validate(
                {"slots": [self._slot(start=_iso(_LATER), end=_iso(_NOW))]}
            )


class TestCounterProposal:
    def test_accepts_valid_payload(self) -> None:
        model = CounterProposalV1.model_validate(
            {
                "slots": [
                    {"start": _iso(_NOW), "end": _iso(_LATER), "preference": 0.9},
                ]
            }
        )
        assert model.type == "counter_proposal"

    def test_rejects_empty_slots(self) -> None:
        with pytest.raises(ValidationError):
            CounterProposalV1.model_validate({"slots": []})

    def test_rejects_more_than_ten_slots(self) -> None:
        slot = {"start": _iso(_NOW), "end": _iso(_LATER), "preference": 0.5}
        with pytest.raises(ValidationError):
            CounterProposalV1.model_validate({"slots": [slot] * 11})

    def test_accepts_ten_slots(self) -> None:
        slot = {"start": _iso(_NOW), "end": _iso(_LATER), "preference": 0.5}
        CounterProposalV1.model_validate({"slots": [slot] * 10})

    def test_rejects_extra_field(self) -> None:
        slot = {"start": _iso(_NOW), "end": _iso(_LATER), "preference": 0.5}
        with pytest.raises(ValidationError):
            CounterProposalV1.model_validate({"slots": [slot], "note": "hi"})


_RESPONSE_SLOT = {"start": _iso(_NOW), "end": _iso(_LATER), "preference": 0.7}


class TestAvailabilityResponse:
    _SLOT = _RESPONSE_SLOT

    def test_accepts_slots_branch(self) -> None:
        model = AvailabilityResponseV1.model_validate({"slots": [self._SLOT]})
        assert model.slots is not None
        assert model.none_available is None
        assert model.type == "availability_response"

    def test_accepts_none_available_branch(self) -> None:
        model = AvailabilityResponseV1.model_validate(
            {"none_available": True, "reason": "no_overlap"}
        )
        assert model.slots is None
        assert model.none_available is True

    def test_rejects_both_branches_present(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityResponseV1.model_validate(
                {
                    "slots": [self._SLOT],
                    "none_available": True,
                    "reason": "no_overlap",
                }
            )

    def test_rejects_neither_branch_present(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityResponseV1.model_validate({})

    def test_rejects_none_available_without_reason(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityResponseV1.model_validate({"none_available": True})

    def test_rejects_reason_with_slots(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityResponseV1.model_validate({"slots": [self._SLOT], "reason": "no_overlap"})

    def test_rejects_bad_reason_value(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityResponseV1.model_validate(
                {"none_available": True, "reason": "not_a_real_reason"}
            )

    def test_rejects_more_than_ten_slots(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityResponseV1.model_validate({"slots": [self._SLOT] * 11})

    def test_rejects_empty_slots_list(self) -> None:
        with pytest.raises(ValidationError):
            AvailabilityResponseV1.model_validate({"slots": []})


class TestConfirm:
    def test_accepts_single_slot(self) -> None:
        model = ConfirmV1.model_validate({"slot": {"start": _iso(_NOW), "end": _iso(_LATER)}})
        assert model.type == "confirm"

    def test_rejects_naive_datetime(self) -> None:
        with pytest.raises(ValidationError):
            ConfirmV1.model_validate({"slot": {"start": _NAIVE.isoformat(), "end": _iso(_LATER)}})

    def test_rejects_start_after_end(self) -> None:
        with pytest.raises(ValidationError):
            ConfirmV1.model_validate({"slot": {"start": _iso(_LATER), "end": _iso(_NOW)}})

    def test_rejects_list_of_slots(self) -> None:
        with pytest.raises(ValidationError):
            ConfirmV1.model_validate({"slot": [{"start": _iso(_NOW), "end": _iso(_LATER)}]})

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            ConfirmV1.model_validate(
                {"slot": {"start": _iso(_NOW), "end": _iso(_LATER)}, "note": "great"}
            )


class TestDecline:
    @pytest.mark.parametrize("reason", ["owner_declined", "no_availability", "expired", "other"])
    def test_accepts_each_reason(self, reason: str) -> None:
        model = DeclineV1.model_validate({"reason": reason})
        assert model.type == "decline"

    def test_rejects_bad_reason(self) -> None:
        with pytest.raises(ValidationError):
            DeclineV1.model_validate({"reason": "changed_my_mind"})

    def test_rejects_missing_reason(self) -> None:
        with pytest.raises(ValidationError):
            DeclineV1.model_validate({})

    def test_rejects_free_text_field(self) -> None:
        with pytest.raises(ValidationError):
            DeclineV1.model_validate({"reason": "other", "note": "sorry, can't make it"})


class TestNeedsClarification:
    def test_accepts_valid_seq(self) -> None:
        model = NeedsClarificationV1.model_validate({"about_seq": 3})
        assert model.type == "needs_clarification"

    def test_accepts_boundary_seq_one(self) -> None:
        NeedsClarificationV1.model_validate({"about_seq": 1})

    @pytest.mark.parametrize("about_seq", [0, -1, -100])
    def test_rejects_non_positive_seq(self, about_seq: int) -> None:
        with pytest.raises(ValidationError):
            NeedsClarificationV1.model_validate({"about_seq": about_seq})

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            NeedsClarificationV1.model_validate({"about_seq": 1, "question": "when?"})


class TestGetSchema:
    def test_returns_registered_class(self) -> None:
        assert get_schema("confirm", 1) is ConfirmV1

    def test_unknown_message_type_raises(self) -> None:
        with pytest.raises(PayloadValidationError):
            get_schema("not_a_type", 1)

    def test_unknown_schema_version_raises(self) -> None:
        with pytest.raises(PayloadValidationError):
            get_schema("confirm", 2)


class TestIsBoundarySafe:
    def test_scheduling_types_are_boundary_safe(self) -> None:
        assert is_boundary_safe("confirm", 1) is True
        assert is_boundary_safe("availability_request", 1) is True

    def test_note_is_not_boundary_safe(self) -> None:
        assert is_boundary_safe("note", 1) is False

    def test_unknown_message_type_raises(self) -> None:
        with pytest.raises(PayloadValidationError):
            is_boundary_safe("not_a_type", 1)


class TestValidatePayload:
    def test_normalizes_valid_payload(self) -> None:
        result = validate_payload("decline", 1, {"reason": "expired"})
        assert result == {"type": "decline", "reason": "expired"}

    def test_normalizes_datetimes_to_iso_strings(self) -> None:
        result = validate_payload(
            "confirm",
            1,
            {"slot": {"start": _iso(_NOW), "end": _iso(_LATER)}},
        )
        assert isinstance(result["slot"]["start"], str)

    def test_raises_payload_validation_error_on_bad_data(self) -> None:
        with pytest.raises(PayloadValidationError):
            validate_payload("decline", 1, {"reason": "not_valid"})

    def test_raises_payload_validation_error_on_unknown_schema(self) -> None:
        with pytest.raises(PayloadValidationError):
            validate_payload("unknown_type", 1, {})


class TestNoteV1:
    def test_accepts_valid_text(self) -> None:
        model = NoteV1.model_validate({"text": "hello"})
        assert model.type == "note"

    def test_rejects_empty_text(self) -> None:
        with pytest.raises(ValidationError):
            NoteV1.model_validate({"text": ""})

    def test_rejects_overlong_text(self) -> None:
        with pytest.raises(ValidationError):
            NoteV1.model_validate({"text": "x" * 4001})

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            NoteV1.model_validate({"text": "hi", "other": 1})


class TestTaskAssignV1:
    def _valid(self, **overrides: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "action": "gather_availability",
            "window": {"start": _iso(_NOW), "end": _iso(_LATER)},
            "duration_min": 30,
        }
        payload.update(overrides)
        return payload

    def test_accepts_valid_gather_availability(self) -> None:
        model = TaskAssignV1.model_validate(self._valid())
        assert model.type == "task_assign"
        assert model.priority == "normal"
        assert model.counterparty_agent_ids == []

    @pytest.mark.parametrize(
        "action", ["gather_availability", "schedule_meeting", "reschedule_meeting"]
    )
    def test_scheduling_actions_require_window_and_duration(self, action: str) -> None:
        with pytest.raises(ValidationError, match="requires 'window' and 'duration_min'"):
            TaskAssignV1.model_validate({"action": action})

    def test_confirm_slot_requires_window(self) -> None:
        with pytest.raises(ValidationError, match="requires 'window'"):
            TaskAssignV1.model_validate({"action": "confirm_slot"})

        model = TaskAssignV1.model_validate(
            {"action": "confirm_slot", "window": {"start": _iso(_NOW), "end": _iso(_LATER)}}
        )
        assert model.action == "confirm_slot"

    @pytest.mark.parametrize("action", ["cancel_meeting", "report_status"])
    def test_actions_with_no_required_fields(self, action: str) -> None:
        model = TaskAssignV1.model_validate({"action": action})
        assert model.window is None
        assert model.duration_min is None

    def test_duplicate_constraints_rejected(self) -> None:
        with pytest.raises(ValidationError, match="duplicates"):
            TaskAssignV1.model_validate(self._valid(constraints=["mornings_only", "mornings_only"]))

    def test_naive_datetime_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TaskAssignV1.model_validate(
                self._valid(window={"start": _NAIVE.isoformat(), "end": _iso(_LATER)})
            )

    def test_extra_field_rejected_no_free_text(self) -> None:
        with pytest.raises(ValidationError):
            TaskAssignV1.model_validate(self._valid(notes="please handle ASAP"))

    def test_counterparty_agent_ids_capped_at_ten(self) -> None:
        with pytest.raises(ValidationError):
            TaskAssignV1.model_validate(
                self._valid(counterparty_agent_ids=[str(uuid.uuid4()) for _ in range(11)])
            )

    def test_duplicate_counterparty_agent_ids_rejected(self) -> None:
        dup = str(uuid.uuid4())
        with pytest.raises(ValidationError, match="duplicates"):
            TaskAssignV1.model_validate(self._valid(counterparty_agent_ids=[dup, dup]))

    def test_registered_in_schema_registry(self) -> None:
        assert get_schema("task_assign", 1) is TaskAssignV1

    def test_validate_payload_normalizes_task_assign(self) -> None:
        result = validate_payload("task_assign", 1, self._valid())
        assert result["type"] == "task_assign"
        assert isinstance(result["window"]["start"], str)

    def test_boundary_safe(self) -> None:
        assert is_boundary_safe("task_assign", 1) is True


class TestTaskReportV1:
    def test_accepts_in_progress(self) -> None:
        model = TaskReportV1.model_validate({"status": "in_progress"})
        assert model.type == "task_report"
        assert model.about_seq is None

    def test_accepts_blocked_with_about_seq(self) -> None:
        model = TaskReportV1.model_validate({"status": "blocked", "about_seq": 1})
        assert model.about_seq == 1

    def test_rejects_bad_status(self) -> None:
        with pytest.raises(ValidationError):
            TaskReportV1.model_validate({"status": "done"})

    def test_rejects_non_positive_about_seq(self) -> None:
        with pytest.raises(ValidationError):
            TaskReportV1.model_validate({"status": "in_progress", "about_seq": 0})

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            TaskReportV1.model_validate({"status": "in_progress", "note": "almost done"})

    def test_boundary_safe(self) -> None:
        assert is_boundary_safe("task_report", 1) is True


class TestTaskCompleteV1:
    def test_accepts_no_fields(self) -> None:
        model = TaskCompleteV1.model_validate({})
        assert model.type == "task_complete"
        assert model.about_seq is None

    def test_accepts_about_seq(self) -> None:
        model = TaskCompleteV1.model_validate({"about_seq": 1})
        assert model.about_seq == 1

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            TaskCompleteV1.model_validate({"summary": "all done"})

    def test_boundary_safe(self) -> None:
        assert is_boundary_safe("task_complete", 1) is True


class TestTaskDeclineV1:
    @pytest.mark.parametrize(
        "reason", ["no_longer_needed", "unable_to_complete", "expired", "other"]
    )
    def test_accepts_each_reason(self, reason: str) -> None:
        model = TaskDeclineV1.model_validate({"reason": reason})
        assert model.type == "task_decline"

    def test_rejects_bad_reason(self) -> None:
        with pytest.raises(ValidationError):
            TaskDeclineV1.model_validate({"reason": "changed_my_mind"})

    def test_rejects_missing_reason(self) -> None:
        with pytest.raises(ValidationError):
            TaskDeclineV1.model_validate({})

    def test_boundary_safe(self) -> None:
        assert is_boundary_safe("task_decline", 1) is True


class TestTaskCancelV1:
    @pytest.mark.parametrize(
        "reason", ["no_longer_needed", "unable_to_complete", "expired", "other"]
    )
    def test_accepts_each_reason(self, reason: str) -> None:
        model = TaskCancelV1.model_validate({"reason": reason})
        assert model.type == "task_cancel"

    def test_rejects_missing_reason(self) -> None:
        with pytest.raises(ValidationError):
            TaskCancelV1.model_validate({})

    def test_boundary_safe(self) -> None:
        assert is_boundary_safe("task_cancel", 1) is True
