"""Message bus: delivers messages between agents, through the guard, and logs every decision."""

import json
from collections import deque
from datetime import datetime
from itertools import count

from guards.protocol_guard import ALLOW, ESCALATE, Message
from protocol.loader import PROJECT_ROOT

LOG_DIR = PROJECT_ROOT / "logs"


class FakeBank:
    """The sandbox's only tool. No real money: it just writes transfers in a ledger."""

    def __init__(self):
        self.ledger = []

    def execute_payment(self, payload):
        transaction_id = f"T-{len(self.ledger) + 1:04d}"
        self.ledger.append({
            "transaction_id": transaction_id,
            "vendor_id": payload["vendor_id"],
            "amount": payload["amount"],
            "account": payload["account"],
        })
        return transaction_id


class MessageBus:
    """All agents talk through the bus. The bus, not the agent, fills in who sent each message."""

    def __init__(self, guard):
        self.guard = guard
        self.agents = {}          # agent name -> agent object
        self.roles = {}           # agent name -> role, set once at registration
        self.tools = {}           # action name -> function; only the bus holds the tools
        self.queue = deque()      # messages waiting to be delivered
        self.log = []             # one record per decision
        self.ids = count(1)

    def register(self, agent, role):
        """Connect an agent to the bus with exactly one role."""
        if agent.name in self.agents:
            raise ValueError(f"agent '{agent.name}' is already registered")
        self.agents[agent.name] = agent
        self.roles[agent.name] = role

    def add_tool(self, action, function):
        """Give the bus a tool. Agents can only reach it through act()."""
        self.tools[action] = function

    def send(self, agent_name, receiver, kind, case_id, payload):
        """An agent sends a message. The guard decides before anything is delivered."""
        message = self._envelope(agent_name, case_id, kind, payload, receiver=receiver)
        decision = self.guard.check(message)
        self._record(agent_name, decision)
        if decision.verdict == ALLOW:
            self.queue.append(message)
        elif decision.verdict == ESCALATE:
            self.queue.append(self._escalation_notice(decision))
        return decision

    def act(self, agent_name, action, case_id, payload):
        """An agent asks to perform an action. The guard decides before the tool runs."""
        message = self._envelope(agent_name, case_id, action, payload, is_action=True)
        decision = self.guard.check(message)
        self._record(agent_name, decision)
        result = None
        if decision.verdict == ALLOW:
            result = self.tools[action](payload)
        elif decision.verdict == ESCALATE:
            self.queue.append(self._escalation_notice(decision))
        return decision, result

    def run(self):                                          # (same as before)
        """Deliver waiting messages, in order, until none are left."""
        while self.queue:
            message = self.queue.popleft()
            for name, role in self.roles.items():
                if role == message.receiver:
                    self.agents[name].handle(message, self)

    def _envelope(self, agent_name, case_id, kind, payload, receiver="", is_action=False):
        """Build a message. The bus writes the sender and the ID; the agent cannot."""
        if agent_name not in self.roles:
            raise PermissionError(f"agent '{agent_name}' is not connected to the bus")
        return Message(
            message_id=f"msg-{next(self.ids):05d}",
            case_id=case_id,
            sender=self.roles[agent_name],
            receiver=receiver,
            kind=kind,
            payload=payload,
            is_action=is_action,
        )

    def _escalation_notice(self, decision):
        """An EFA-style notice for the human: what is waiting, why, and the incident ID."""
        original = decision.message
        return Message(
            message_id=f"notice-{decision.incident_id}",
            case_id=original.case_id,
            sender="guard",
            receiver=self.guard.protocol.escalation["role"],
            kind="escalation_notice",
            payload={
                "incident_id": decision.incident_id,
                "reason": decision.reason,
                "requested_by": original.sender,
                "request": original.kind,
                "details": original.payload,
            },
        )

    def _record(self, agent_name, decision): 
        """Add one decision to the log."""
        message = decision.message
        self.log.append({
            "time": datetime.now().isoformat(timespec="seconds"),
            "agent": agent_name,
            "message_id": message.message_id,
            "case_id": message.case_id,
            "sender": message.sender,
            "receiver": message.receiver,
            "kind": message.kind,
            "is_action": message.is_action,
            "payload": message.payload,
            "verdict": decision.verdict,
            "reason": decision.reason,
            "incident_id": decision.incident_id,
        })

    def save_log(self, name): 
        """Write the log as JSON Lines: one decision per line."""
        LOG_DIR.mkdir(exist_ok=True)
        path = LOG_DIR / f"{name}.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for record in self.log:
                f.write(json.dumps(record, default=str) + "\n")
        return path
    