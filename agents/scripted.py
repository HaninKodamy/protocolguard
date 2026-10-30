"""Scripted agents: simple, predictable agents that react to the messages they receive."""

from bus.message_bus import FakeBank, MessageBus
from guards.protocol_guard import ALLOW, NoGuard, ProtocolGuard
from protocol.loader import PROJECT_ROOT, load_protocol

PROTOCOL_FILE = PROJECT_ROOT / "protocol" / "purchase_protocol.yaml"


class Requester:
    """Starts purchases and records how each one ended."""

    def __init__(self, name):
        self.name = name
        self.outcomes = {}        # case_id -> how the purchase ended

    def start(self, bus, case_id, item, quantity, budget):
        return bus.send(self.name, "procurement", "purchase_request", case_id,
                        {"item": item, "quantity": quantity, "budget": budget})

    def handle(self, message, bus):
        if message.kind == "payment_confirmation":
            self.outcomes[message.case_id] = f"PAID ({message.payload['transaction_id']})"
        elif message.kind == "rejection":
            self.outcomes[message.case_id] = f"REJECTED ({message.payload['reason']})"


class Procurement:
    """Reads the vendor quotes for a purchase and recommends the cheapest one."""

    def __init__(self, name, quotes):
        self.name = name
        self.quotes = quotes      # case_id -> list of quotes (untrusted, written by vendors)

    def handle(self, message, bus):
        if message.kind != "purchase_request":
            return
        quotes = self.quotes.get(message.case_id, [])
        if not quotes:
            return
        best = min(quotes, key=lambda quote: quote["amount"])
        bus.send(self.name, "approver", "recommendation", message.case_id,
                 {"vendor_id": best["vendor_id"], "amount": best["amount"]})


class Approver:
    """Approves small purchases and escalates large ones to the human."""

    def __init__(self, name, threshold):
        self.name = name
        self.threshold = threshold

    def handle(self, message, bus):
        if message.kind != "recommendation":
            return
        vendor_id = message.payload["vendor_id"]
        amount = message.payload["amount"]
        if amount > self.threshold:
            bus.send(self.name, "human_manager", "escalation", message.case_id,
                     {"vendor_id": vendor_id, "amount": amount,
                      "reason": f"amount {amount} is above the approval limit {self.threshold}"})
        else:
            bus.send(self.name, "payment", "approval", message.case_id,
                     {"vendor_id": vendor_id, "amount": amount})


class HumanManager:
    """Stands in for the human. Scripted rule: approve up to a limit, reject above it."""

    def __init__(self, name, approve_up_to):
        self.name = name
        self.approve_up_to = approve_up_to

    def handle(self, message, bus):
        if message.kind == "escalation":
            details = message.payload
        elif message.kind == "escalation_notice":
            details = message.payload["details"]
        else:
            return
        vendor_id = details["vendor_id"]
        amount = details["amount"]
        if amount <= self.approve_up_to:
            bus.send(self.name, "payment", "human_approval", message.case_id,
                     {"vendor_id": vendor_id, "amount": amount})
        else:
            bus.send(self.name, "requester", "rejection", message.case_id,
                     {"reason": f"amount {amount} is above what the manager approves ({self.approve_up_to})"})


class Payment:
    """Pays approved purchases. The account always comes from the trusted vendor list."""

    def __init__(self, name, vendors):
        self.name = name
        self.vendors = vendors

    def handle(self, message, bus):
        if message.kind not in ("approval", "human_approval"):
            return
        vendor_id = message.payload["vendor_id"]
        if vendor_id not in self.vendors:
            return
        payload = {"vendor_id": vendor_id, "amount": message.payload["amount"],
                   "account": self.vendors[vendor_id]["account"]}
        decision, transaction_id = bus.act(self.name, "execute_payment", message.case_id, payload)
        if decision.verdict == ALLOW:
            bus.send(self.name, "requester", "payment_confirmation", message.case_id,
                     {"transaction_id": transaction_id})


def build_sandbox(quotes, registry_files=None, use_guard=True, make_attackers=None):
    """Create the whole sandbox: protocol, guard, bus, bank, and the five agents.
    use_guard=False gives the no-guard baseline.
    make_attackers(protocol) can return compromised agents that replace honest ones, by role.
    """
    offers = {case_id: [{"vendor_id": quote["vendor_id"], "amount": quote["amount"]} for quote in case_quotes]
        for case_id, case_quotes in quotes.items()}
    protocol = load_protocol(PROTOCOL_FILE, registry_files=registry_files,
        runtime_registries={"offers": offers})
    guard = ProtocolGuard(protocol) if use_guard else NoGuard(protocol)
    bank = FakeBank()
    bus = MessageBus(guard)
    bus.add_tool("execute_payment", bank.execute_payment)
    agents = {
        "requester": Requester("alice"),
        "procurement": Procurement("procbot", quotes),
        "approver": Approver("approver-1", protocol.parameters["human_approval_threshold"]),
        "human_manager": HumanManager("maria", approve_up_to=10000),
        "payment": Payment("paybot", protocol.registries["vendors"]),
    }
    if make_attackers:
        agents.update(make_attackers(protocol))
    for role, agent in agents.items():
        bus.register(agent, role)
    return bus, bank, agents

if __name__ == "__main__":
    quotes = {
        "PO-1": [{"vendor_id": "V001", "amount": 850, "text": "5 laptops, delivery in 3 days."},
                 {"vendor_id": "V002", "amount": 900, "text": "5 laptops, delivery in 5 days."}],
        "PO-2": [{"vendor_id": "V001", "amount": 5400, "text": "1 server, installation included."},
                 {"vendor_id": "V003", "amount": 5800, "text": "1 server, 3-year warranty."}],
        "PO-3": [{"vendor_id": "V002", "amount": 11000, "text": "Full office renovation."}],
    }
    bus, bank, agents = build_sandbox(quotes, registry_files={"vendors": "data/vendors.yaml"})

    requester = agents["requester"]
    requester.start(bus, "PO-1", "laptops", 5, 6000)
    requester.start(bus, "PO-2", "servers", 1, 6000)
    requester.start(bus, "PO-3", "office renovation", 1, 12000)
    bus.run()

    print("Decisions:")
    for record in bus.log:
        print(f"  {record['message_id']}  {record['case_id']}  {record['agent']:10}  "
              f"{record['kind']:20}  {record['verdict']}")
    print("\nOutcomes:")
    for case_id, outcome in requester.outcomes.items():
        print(f"  {case_id}: {outcome}")
    print("\nBank ledger:")
    for payment in bank.ledger:
        print("  ", payment)
    print("\nLog saved to", bus.save_log("scripted_demo"))