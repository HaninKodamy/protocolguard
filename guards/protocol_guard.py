"""ProtocolGuard: checks every message and action against the protocol."""

from dataclasses import dataclass, field
from protocol.loader import PROJECT_ROOT, load_protocol

# The three possible decisions.
ALLOW = "ALLOW"
BLOCK = "BLOCK"
ESCALATE = "ESCALATE"


@dataclass
class Message:
    """One message between agents, or one action an agent wants to perform."""
    message_id: str          # unique ID, so the same message can't be used twice
    case_id: str             # which purchase this belongs to
    sender: str              # role of the agent that sent it (filled in by the bus)
    kind: str                # message type or action name, e.g. "approval"
    payload: dict            # the content, e.g. {"vendor_id": "V001", "amount": 850}
    receiver: str = ""       # role it is sent to (empty for actions)
    is_action: bool = False  # True for actions like execute_payment


@dataclass
class Case:
    """What the guard remembers about one purchase."""
    case_id: str
    state: str
    memory: dict = field(default_factory=dict)
    actions_done: dict = field(default_factory=dict)


@dataclass
class Decision:
    """The guard's answer for one message or action."""
    verdict: str             # ALLOW, BLOCK or ESCALATE
    reason: str              # why
    message: Message
    incident_id: str = ""    # set for BLOCK and ESCALATE

def is_number(value):
    """True for real numbers. Text like "850" and True/False do not count."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def describe(condition, value):
    """A short explanation of a failed condition, for the incident report."""
    if "case_field" in condition:
        target = f"the case's {condition['case_field']}"
    elif "parameter" in condition:
        target = f"parameter {condition['parameter']}"
    else:
        target = f"registry {condition['registry']}"
    return f"{condition['type']} failed: {condition['field']}={value!r}, checked against {target}"

class ProtocolGuard:
    """Checks messages against a protocol and remembers every case."""

    def __init__(self, protocol):
        self.protocol = protocol
        self.cases = {}         
        self.seen_ids = set() 
        self.incident_count = 0

    def check(self, message):
        """Decide ALLOW, BLOCK or ESCALATE for one message or action."""
        # 1. Replay: the same message can never be used twice.
        if message.message_id in self.seen_ids:
            return self._refuse(BLOCK, f"replay: message {message.message_id} was already used", message)
        self.seen_ids.add(message.message_id)

        # 2. Deny by default: anything not in the protocol is never allowed.
        rules = self.protocol.actions if message.is_action else self.protocol.messages
        rule = rules.get(message.kind)
        if rule is None:
            what = "action" if message.is_action else "message type"
            return self._refuse(BLOCK, f"unknown {what} '{message.kind}'", message)

        # 3. Find the case. A new purchase starts in the initial state.
        case = self.cases.get(message.case_id)
        state = case.state if case else self.protocol.states["initial"]

        # 4. Who, to whom, when (different for messages and actions), and what.
        if message.is_action:
            problem = self._action_problem(rule, message, state, case)
        else:
            problem = self._message_problem(rule, message, state)
        if problem:
            return self._refuse(BLOCK, problem, message)
        missing = [name for name in rule["required_fields"] if name not in message.payload]
        if missing:
            return self._refuse(BLOCK, f"incomplete message: missing {missing}", message)

        # 5. Value conditions. A failed "block" always wins over a failed "escalate".
        verdict, reason = self._check_conditions(rule, message, case)
        if verdict == BLOCK:
            return self._refuse(BLOCK, reason, message)

        # 6. Create the case if it is new.
        if case is None:
            case = Case(case_id=message.case_id, state=state)
            self.cases[message.case_id] = case

        # 7. Escalate: the case waits for the human. Nothing moves forward.
        if verdict == ESCALATE:
            case.state = self.protocol.escalation["state"]
            who = self.protocol.escalation["role"]
            return self._refuse(ESCALATE, f"{reason}; waiting for {who}", message)

        # 8. Allowed. An action is counted; a message moves the case forward.
        if message.is_action:
            case.actions_done[message.kind] = case.actions_done.get(message.kind, 0) + 1
        else:
            case.state = rule["to_state"]
            for name in rule["required_fields"]:
                case.memory[name] = message.payload[name]
        return Decision(verdict=ALLOW, reason="all rules satisfied", message=message)

    def _message_problem(self, rule, message, state):
        """Who, to whom and when, for messages. Returns a reason, or "" if fine."""
        if message.sender not in rule["senders"]:
            return f"role violation: {message.sender} may not send {message.kind}"
        if message.receiver not in rule["receivers"]:
            return f"routing violation: {message.kind} may not go to {message.receiver}"
        if state not in rule["from_states"]:
            return f"order violation: {message.kind} not allowed in state {state}"
        return ""

    def _action_problem(self, rule, message, state, case):
        """Who, when and how often, for actions. Returns a reason, or "" if fine."""
        if message.sender not in rule["performers"]:
            return f"role violation: {message.sender} may not perform {message.kind}"
        if state not in rule["allowed_states"]:
            return f"order violation: {message.kind} not allowed in state {state}"
        done = case.actions_done.get(message.kind, 0) if case else 0
        if done >= rule["max_per_case"]:
            return f"repeat violation: {message.kind} already done {done} time(s) in this case"
        return ""

    def _check_conditions(self, rule, message, case):
        """Check all value conditions. Returns (verdict, reason)."""
        memory = case.memory if case else {}
        escalate_reason = ""
        for condition in rule.get("conditions", []):
            if self._condition_holds(condition, message.payload, memory):
                continue
            reason = describe(condition, message.payload.get(condition["field"]))
            if condition["on_fail"] == "block":
                return BLOCK, reason
            escalate_reason = escalate_reason or reason
        if escalate_reason:
            return ESCALATE, escalate_reason
        return ALLOW, ""

    def _condition_holds(self, condition, payload, memory):
        """Return True if one condition is satisfied."""
        kind = condition["type"]
        value = payload.get(condition["field"])
        if kind == "in_registry":
            registry = self.protocol.registries[condition["registry"]]
            return isinstance(value, str) and value in registry
        if kind == "matches_registry":
            key = payload.get(condition["key_field"])
            if not isinstance(key, str):
                return False
            entry = self.protocol.registries[condition["registry"]].get(key)
            return entry is not None and entry.get(condition["registry_field"]) == value
        if kind == "matches_case":
            field_name = condition["case_field"]
            return field_name in memory and memory[field_name] == value
        if kind == "max_from_case":
            limit = memory.get(condition["case_field"])
            return is_number(value) and is_number(limit) and value <= limit
        if kind == "max_parameter":
            limit = self.protocol.parameters[condition["parameter"]]
            return is_number(value) and value <= limit
        return False

    def _refuse(self, verdict, reason, message):
        """Create a BLOCK or ESCALATE decision with a new incident ID."""
        self.incident_count += 1
        incident_id = f"INC-{self.incident_count:04d}"
        return Decision(verdict=verdict, reason=reason, message=message, incident_id=incident_id)

if __name__ == "__main__":
    protocol = load_protocol(PROJECT_ROOT / "protocol" / "purchase_protocol.yaml")
    guard = ProtocolGuard(protocol)

    def send(message_id, case_id, sender, receiver, kind, payload, is_action=False):
        message = Message(message_id=message_id, case_id=case_id, sender=sender,
                          receiver=receiver, kind=kind, payload=payload, is_action=is_action)
        decision = guard.check(message)
        target = "(action)" if is_action else receiver
        line = f"{message_id:4} {case_id:8} {sender:13} -> {target:13} {kind:16} {decision.verdict:8}"
        if decision.incident_id:
            line += f" {decision.incident_id}: {decision.reason}"
        print(line)

    # PO-0001: a normal small purchase.
    send("m1", "PO-0001", "requester", "procurement", "purchase_request", {"item": "laptops", "quantity": 5, "budget": 6000})
    send("m2", "PO-0001", "procurement", "approver", "recommendation", {"vendor_id": "V001", "amount": 850})
    send("m3", "PO-0001", "approver", "payment", "approval", {"vendor_id": "V001", "amount": 850})

    # PO-0002: an injected quote makes procurement recommend an unknown vendor.
    send("m4", "PO-0002", "requester", "procurement", "purchase_request", {"item": "chairs", "quantity": 10, "budget": 3000})
    send("m5", "PO-0002", "procurement", "approver", "recommendation", {"vendor_id": "V999", "amount": 2900})

    # PO-0003: the recommendation is above the budget.
    send("m6", "PO-0003", "requester", "procurement", "purchase_request", {"item": "monitors", "quantity": 2, "budget": 1000})
    send("m7", "PO-0003", "procurement", "approver", "recommendation", {"vendor_id": "V002", "amount": 1500})

    # PO-0004: a vendor swap, then a large purchase that needs the human.
    send("m8", "PO-0004", "requester", "procurement", "purchase_request", {"item": "servers", "quantity": 1, "budget": 6000})
    send("m9", "PO-0004", "procurement", "approver", "recommendation", {"vendor_id": "V001", "amount": 5400})
    send("m10", "PO-0004", "approver", "payment", "approval", {"vendor_id": "V002", "amount": 5400})
    send("m11", "PO-0004", "approver", "payment", "approval", {"vendor_id": "V001", "amount": 5400})
    send("m12", "PO-0004", "human_manager", "payment", "human_approval", {"vendor_id": "V001", "amount": 5400})

    # PO-0005: type confusion, the amount is sent as text.
    send("m13", "PO-0005", "requester", "procurement", "purchase_request", {"item": "desks", "quantity": 4, "budget": 6000})
    send("m14", "PO-0005", "procurement", "approver", "recommendation", {"vendor_id": "V001", "amount": "850"})

    # PO-0001 is approved: now the payment, and attacks on it.
    send("m15", "PO-0001", "procurement", "", "execute_payment", {"vendor_id": "V001", "amount": 850, "account": "FAKE-SE-0001"}, is_action=True)
    send("m16", "PO-0001", "payment", "", "execute_payment", {"vendor_id": "V001", "amount": 850, "account": "XYZ-ATTACKER"}, is_action=True)
    send("m17", "PO-0001", "payment", "", "execute_payment", {"vendor_id": "V001", "amount": 850, "account": "FAKE-SE-0001"}, is_action=True)
    send("m18", "PO-0001", "payment", "", "execute_payment", {"vendor_id": "V001", "amount": 850, "account": "FAKE-SE-0001"}, is_action=True)
    send("m19", "PO-0001", "payment", "requester", "payment_confirmation", {"transaction_id": "T-0001"})

    # PO-0002 was never approved: payment must be impossible.
    send("m20", "PO-0002", "payment", "", "execute_payment", {"vendor_id": "V001", "amount": 2900, "account": "FAKE-SE-0001"}, is_action=True)

    print()
    for case in guard.cases.values():
        print(case.case_id, case.state)