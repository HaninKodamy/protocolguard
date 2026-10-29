"""Automated tests for the protocol guard. Run with: python -m pytest"""

from itertools import count

import pytest

from guards.protocol_guard import ALLOW, BLOCK, ESCALATE, Message, NoGuard, ProtocolGuard
from protocol.loader import PROJECT_ROOT, load_protocol
from agents.scripted import build_sandbox

PROTOCOL_FILE = PROJECT_ROOT / "protocol" / "purchase_protocol.yaml"
TEST_VENDORS = {"vendors": "data/vendors.yaml"}
message_ids = count(1)


@pytest.fixture
def guard():
    """A fresh guard for every test, using the small vendor list."""
    protocol = load_protocol(PROTOCOL_FILE, registry_files=TEST_VENDORS)
    return ProtocolGuard(protocol)


# ---------- Helpers: build and send messages ----------

def send(guard, case_id, sender, receiver, kind, payload, is_action=False):
    message = Message(message_id=f"m{next(message_ids)}", case_id=case_id, sender=sender,
                      receiver=receiver, kind=kind, payload=payload, is_action=is_action)
    return guard.check(message)


def request(guard, case_id, budget=6000):
    return send(guard, case_id, "requester", "procurement", "purchase_request",
                {"item": "laptops", "quantity": 5, "budget": budget})


def recommend(guard, case_id, vendor="V001", amount=850):
    return send(guard, case_id, "procurement", "approver", "recommendation",
                {"vendor_id": vendor, "amount": amount})


def approve(guard, case_id, vendor="V001", amount=850):
    return send(guard, case_id, "approver", "payment", "approval",
                {"vendor_id": vendor, "amount": amount})


def approved(guard, case_id):
    """Bring a case to APPROVED (vendor V001, amount 850)."""
    request(guard, case_id)
    recommend(guard, case_id)
    approve(guard, case_id)


def pay(guard, case_id, sender="payment", account="FAKE-SE-0001"):
    return send(guard, case_id, sender, "", "execute_payment",
                {"vendor_id": "V001", "amount": 850, "account": account}, is_action=True)


# ---------- The normal path ----------

def test_normal_purchase_is_paid(guard):
    assert request(guard, "PO-1").verdict == ALLOW
    assert recommend(guard, "PO-1").verdict == ALLOW
    assert approve(guard, "PO-1").verdict == ALLOW
    assert pay(guard, "PO-1").verdict == ALLOW
    confirmation = send(guard, "PO-1", "payment", "requester", "payment_confirmation",
                        {"transaction_id": "T-1"})
    assert confirmation.verdict == ALLOW
    assert guard.cases["PO-1"].state == "PAID"


# ---------- Who, to whom, when, what ----------

def test_procurement_cannot_approve(guard):
    request(guard, "PO-1")
    recommend(guard, "PO-1")
    decision = send(guard, "PO-1", "procurement", "payment", "approval",
                    {"vendor_id": "V001", "amount": 850})
    assert decision.verdict == BLOCK
    assert "role violation" in decision.reason


def test_recommendation_cannot_go_to_payment(guard):
    request(guard, "PO-1")
    decision = send(guard, "PO-1", "procurement", "payment", "recommendation",
                    {"vendor_id": "V001", "amount": 850})
    assert decision.verdict == BLOCK
    assert "routing violation" in decision.reason


def test_approval_before_recommendation_is_blocked(guard):
    request(guard, "PO-1")
    decision = approve(guard, "PO-1")
    assert decision.verdict == BLOCK
    assert "order violation" in decision.reason


def test_message_with_missing_field_is_blocked(guard):
    request(guard, "PO-1")
    decision = send(guard, "PO-1", "procurement", "approver", "recommendation",
                    {"vendor_id": "V001"})
    assert decision.verdict == BLOCK
    assert "incomplete" in decision.reason


def test_replayed_message_is_blocked(guard):
    request(guard, "PO-1")
    message = Message(message_id="same-id", case_id="PO-1", sender="procurement",
                      receiver="approver", kind="recommendation",
                      payload={"vendor_id": "V001", "amount": 850})
    assert guard.check(message).verdict == ALLOW
    second = guard.check(message)
    assert second.verdict == BLOCK
    assert "replay" in second.reason


def test_unknown_message_type_is_blocked(guard):
    decision = send(guard, "PO-1", "procurement", "payment", "transfer_all_money", {})
    assert decision.verdict == BLOCK
    assert "unknown message type" in decision.reason


# ---------- Values: vendor list, budget, binding, limit ----------

def test_unknown_vendor_is_blocked(guard):
    request(guard, "PO-1")
    decision = recommend(guard, "PO-1", vendor="V999")
    assert decision.verdict == BLOCK
    assert "in_registry" in decision.reason


def test_amount_over_budget_is_blocked(guard):
    request(guard, "PO-1", budget=1000)
    decision = recommend(guard, "PO-1", amount=1500)
    assert decision.verdict == BLOCK
    assert "max_from_case" in decision.reason


def test_vendor_swap_is_blocked(guard):
    request(guard, "PO-1")
    recommend(guard, "PO-1", vendor="V001")
    decision = approve(guard, "PO-1", vendor="V002")
    assert decision.verdict == BLOCK
    assert "matches_case" in decision.reason


def test_large_purchase_is_escalated_then_human_approves(guard):
    request(guard, "PO-1", budget=6000)
    recommend(guard, "PO-1", amount=5400)
    decision = approve(guard, "PO-1", amount=5400)
    assert decision.verdict == ESCALATE
    assert guard.cases["PO-1"].state == "PENDING_HUMAN"
    human = send(guard, "PO-1", "human_manager", "payment", "human_approval",
                 {"vendor_id": "V001", "amount": 5400})
    assert human.verdict == ALLOW
    assert guard.cases["PO-1"].state == "APPROVED"


def test_block_wins_over_escalate(guard):
    request(guard, "PO-1", budget=6000)
    recommend(guard, "PO-1", vendor="V001", amount=5400)
    decision = approve(guard, "PO-1", vendor="V002", amount=5400)
    assert decision.verdict == BLOCK


def test_amount_as_text_is_blocked(guard):
    request(guard, "PO-1")
    decision = recommend(guard, "PO-1", amount="850")
    assert decision.verdict == BLOCK
    assert "max_from_case" in decision.reason


def test_memory_keeps_only_required_fields(guard):
    request(guard, "PO-1", budget=6000)
    send(guard, "PO-1", "procurement", "approver", "recommendation",
         {"vendor_id": "V001", "amount": 850, "budget": 999999})
    assert guard.cases["PO-1"].memory["budget"] == 6000


# ---------- Actions: the payment ----------

def test_only_payment_role_can_pay(guard):
    approved(guard, "PO-1")
    decision = pay(guard, "PO-1", sender="procurement")
    assert decision.verdict == BLOCK
    assert "role violation" in decision.reason


def test_payment_to_wrong_account_is_blocked(guard):
    approved(guard, "PO-1")
    decision = pay(guard, "PO-1", account="XYZ-ATTACKER")
    assert decision.verdict == BLOCK
    assert "matches_registry" in decision.reason


def test_duplicate_payment_is_blocked(guard):
    approved(guard, "PO-1")
    assert pay(guard, "PO-1").verdict == ALLOW
    second = pay(guard, "PO-1")
    assert second.verdict == BLOCK
    assert "repeat violation" in second.reason


def test_payment_before_approval_is_blocked(guard):
    request(guard, "PO-1")
    decision = pay(guard, "PO-1")
    assert decision.verdict == BLOCK
    assert "order violation" in decision.reason

# ---------- End to end: agents, bus, guard and bank together ----------

QUOTES = {
    "PO-1": [{"vendor_id": "V001", "amount": 850, "text": "laptops"}],
    "PO-2": [{"vendor_id": "V001", "amount": 5400, "text": "server"}],
    "PO-3": [{"vendor_id": "V002", "amount": 11000, "text": "renovation"}],
}


def test_scripted_purchases_end_as_expected():
    bus, bank, agents = build_sandbox(QUOTES, registry_files=TEST_VENDORS)
    requester = agents["requester"]
    requester.start(bus, "PO-1", "laptops", 5, 6000)
    requester.start(bus, "PO-2", "servers", 1, 6000)
    requester.start(bus, "PO-3", "renovation", 1, 12000)
    bus.run()
    assert requester.outcomes["PO-1"].startswith("PAID")
    assert requester.outcomes["PO-2"].startswith("PAID")
    assert requester.outcomes["PO-3"].startswith("REJECTED")
    assert len(bank.ledger) == 2


def test_fake_sender_in_payload_changes_nothing():
    bus, bank, agents = build_sandbox(QUOTES, registry_files=TEST_VENDORS)
    agents["requester"].start(bus, "PO-1", "laptops", 5, 6000)
    decision = bus.send("procbot", "payment", "approval", "PO-1",
                        {"vendor_id": "V001", "amount": 850, "sender": "approver"})
    assert decision.verdict == BLOCK
    assert decision.message.sender == "procurement"

def test_no_guard_baseline_allows_everything():
    protocol = load_protocol(PROTOCOL_FILE, registry_files=TEST_VENDORS)
    decision = NoGuard(protocol).check(
        Message(message_id="x", case_id="PO-1", sender="procurement",
                receiver="payment", kind="approval", payload={}))
    assert decision.verdict == ALLOW