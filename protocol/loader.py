"""Load and check a ProtocolGuard protocol file."""

from pathlib import Path

import yaml
from dataclasses import dataclass


PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONDITION_TYPES = {
    "in_registry": {"field", "registry"},
    "max_from_case": {"field", "case_field"},
    "matches_case": {"field", "case_field"},
    "max_parameter": {"field", "parameter"},
    "matches_registry": {"field", "registry", "key_field", "registry_field"},
}
ON_FAIL_OPTIONS = {"block", "escalate"}

class ProtocolError(Exception):
    """Raised when a protocol file has mistakes."""


@dataclass
class Protocol:
    """A loaded and checked protocol, ready for the guard."""
    name: str
    version: str
    parameters: dict
    roles: dict
    states: dict
    messages: dict
    actions: dict
    registries: dict
    escalation: dict

def read_yaml(path):
    """Open a YAML file and return its contents as Python data."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_registries(raw):
    """Read every registry file named in the protocol."""
    registries = {}
    for name, relative_path in raw.get("registries", {}).items():
        data = read_yaml(PROJECT_ROOT / relative_path)
        if name not in data:
            raise ValueError(f"Registry file {relative_path} must start with '{name}:'")
        registries[name] = data[name]
    return registries

def check_conditions(where, conditions, raw, registries):
    """Check a list of conditions. Returns a list of error messages."""
    errors = []
    parameters = raw.get("parameters", {})
    for number, condition in enumerate(conditions, start=1):
        place = f"{where}, condition {number}"
        kind = condition.get("type")
        if kind not in CONDITION_TYPES:
            errors.append(f"{place}: unknown type '{kind}'")
            continue
        missing = CONDITION_TYPES[kind] - set(condition)
        if missing:
            errors.append(f"{place} ({kind}): missing {sorted(missing)}")
        if condition.get("on_fail") not in ON_FAIL_OPTIONS:
            errors.append(f"{place}: on_fail must be 'block' or 'escalate'")
        if "registry" in condition and condition["registry"] not in registries:
            errors.append(f"{place}: unknown registry '{condition['registry']}'")
        if "parameter" in condition and condition["parameter"] not in parameters:
            errors.append(f"{place}: unknown parameter '{condition['parameter']}'")
    return errors

def check_protocol(raw, registries):
    """Check the protocol for mistakes. Returns a list of error messages."""
    errors = []
    roles = set(raw.get("roles", {}))
    states_section = raw.get("states", {})
    states = set(states_section.get("all", []))

    # The initial and final states must be real states.
    initial = states_section.get("initial")
    if initial not in states:
        errors.append(f"initial state '{initial}' is not in the state list")
    for state in states_section.get("final", []):
        if state not in states:
            errors.append(f"final state '{state}' is not in the state list")

    # Escalation must name a real role and a real state.
    escalation = raw.get("escalation", {})
    if escalation.get("role") not in roles:
        errors.append(f"escalation: unknown role '{escalation.get('role')}'")
    if escalation.get("state") not in states:
        errors.append(f"escalation: unknown state '{escalation.get('state')}'")

    # Every message must name real roles and real states.
    for name, rule in raw.get("messages", {}).items():
        where = f"message '{name}'"
        if not rule.get("senders"):
            errors.append(f"{where}: has no senders")
        if not rule.get("receivers"):
            errors.append(f"{where}: has no receivers")
        for role in rule.get("senders", []) + rule.get("receivers", []):
            if role not in roles:
                errors.append(f"{where}: unknown role '{role}'")
        for state in rule.get("from_states", []):
            if state not in states:
                errors.append(f"{where}: unknown from_state '{state}'")
        if rule.get("to_state") not in states:
            errors.append(f"{where}: unknown to_state '{rule.get('to_state')}'")
        errors += check_conditions(where, rule.get("conditions", []), raw, registries)

    # Every action must name real roles and real states.
    for name, rule in raw.get("actions", {}).items():
        where = f"action '{name}'"
        if not rule.get("performers"):
            errors.append(f"{where}: has no performers")
        if not rule.get("allowed_states"):
            errors.append(f"{where}: has no allowed_states")
        limit = rule.get("max_per_case")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            errors.append(f"{where}: max_per_case must be a whole number, 1 or more")
        for role in rule.get("performers", []):
            if role not in roles:
                errors.append(f"{where}: unknown role '{role}'")
        for state in rule.get("allowed_states", []):
            if state not in states:
                errors.append(f"{where}: unknown state '{state}'")
        errors += check_conditions(where, rule.get("conditions", []), raw, registries)

    return errors

def load_protocol(path):
    """Read, check and return a protocol. Stops with an error if anything is wrong."""
    raw = read_yaml(path)
    registries = load_registries(raw)
    errors = check_protocol(raw, registries)
    if errors:
        raise ProtocolError("Protocol has problems:\n  - " + "\n  - ".join(errors))
    return Protocol(
        name=raw["protocol"]["name"],
        version=str(raw["protocol"]["version"]),
        parameters=raw.get("parameters", {}),
        roles=raw["roles"],
        states=raw["states"],
        messages=raw.get("messages", {}),
        actions=raw.get("actions", {}),
        registries=registries,
        escalation=raw.get("escalation", {}),
    )

def print_summary(protocol):
    """Print a short, readable overview of a protocol."""
    print(f"Protocol: {protocol.name} (version {protocol.version})")
    print(f"Roles:    {', '.join(protocol.roles)}")
    print(f"States:   {', '.join(protocol.states['all'])}")
    print(f"Escalation: {protocol.escalation['role']} (case waits in {protocol.escalation['state']})")
    print("\nMessages:")
    for name, rule in protocol.messages.items():
        route = f"{'/'.join(rule['senders'])} -> {'/'.join(rule['receivers'])}"
        steps = f"{'/'.join(rule['from_states'])} -> {rule['to_state']}"
        count = len(rule.get("conditions", []))
        print(f"  {name:22} {route:36} {steps:38} conditions: {count}")
    print("\nActions:")
    for name, rule in protocol.actions.items():
        who = "/".join(rule["performers"])
        when = "/".join(rule["allowed_states"])
        count = len(rule.get("conditions", []))
        print(f"  {name:22} by {who} in {when}, max {rule['max_per_case']} per case   conditions: {count}")
    print()
    for name, entries in protocol.registries.items():
        print(f"Registry '{name}': {len(entries)} entries")


if __name__ == "__main__":
    try:
        protocol = load_protocol(PROJECT_ROOT / "protocol" / "purchase_protocol.yaml")
    except ProtocolError as error:
        print(error)
    else:
        print_summary(protocol)
        print("\nProtocol is valid.")