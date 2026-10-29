"""Run every attack with and without the guard, and print the results table."""

import csv
import time

from bpi.workload import sample_purchases
from agents.scripted import build_sandbox
from attacks.scenarios import ATTACKS, NORMAL_PURCHASES, NORMAL_QUOTES
from protocol.loader import PROJECT_ROOT

TEST_VENDORS = {"vendors": "data/vendors.yaml"}
RESULTS_DIR = PROJECT_ROOT / "results"
SETTINGS = [(False, "no_guard"), (True, "guard")]


def run_scenario(quotes, purchases, use_guard, make_attackers=None, log_name=None,
                 registry_files=TEST_VENDORS):
    """Run one scenario in a fresh sandbox. Returns the bank, the bus and the requester."""
    bus, bank, agents = build_sandbox(quotes, registry_files=registry_files,
                                      use_guard=use_guard, make_attackers=make_attackers)
    for case_id, item, quantity, budget in purchases:
        agents["requester"].start(bus, case_id, item, quantity, budget)
    bus.run()
    if log_name:
        bus.save_log(log_name)
    return bank, bus, agents["requester"]


def count_incidents(bus):
    """How many decisions were BLOCK or ESCALATE."""
    return sum(1 for record in bus.log if record["incident_id"])


def run_attacks():
    """Run every attack without and with the guard. Returns one row per attack."""
    rows = []
    for attack in ATTACKS:
        row = {"attack": attack.name, "family": attack.family, "compromised": attack.compromised}
        for use_guard, label in SETTINGS:
            bank, bus, _ = run_scenario(attack.quotes, attack.purchases, use_guard,
                                        attack.make_attackers, log_name=f"{attack.name}_{label}")
            row[f"{label}_succeeded"] = attack.succeeded(bank)
            row[f"{label}_incidents"] = count_incidents(bus)
        rows.append(row)
    return rows


def run_normal():
    """Run the legitimate purchases without and with the guard."""
    results = {}
    for use_guard, label in SETTINGS:
        bank, bus, requester = run_scenario(NORMAL_QUOTES, NORMAL_PURCHASES, use_guard,
                                            log_name=f"normal_{label}")
        completed = sum(1 for outcome in requester.outcomes.values() if outcome.startswith("PAID"))
        results[label] = (completed, len(NORMAL_PURCHASES), count_incidents(bus))
    return results

def run_workload(n=1000):
    """Real BPI purchases with the real vendor list, without and with the guard."""
    quotes, purchases = sample_purchases(n)
    results = {}
    for use_guard, label in SETTINGS:
        start = time.perf_counter()
        bank, bus, requester = run_scenario(quotes, purchases, use_guard,
                                            log_name=f"bpi_workload_{label}", registry_files=None)
        seconds = time.perf_counter() - start
        outcomes = list(requester.outcomes.values())
        to_human = sum(1 for r in bus.log
                       if (r["kind"] == "escalation" and r["verdict"] == "ALLOW") or r["verdict"] == "ESCALATE")
        results[label] = {
            "purchases": len(purchases),
            "paid": sum(1 for o in outcomes if o.startswith("PAID")),
            "rejected_by_human": sum(1 for o in outcomes if o.startswith("REJECTED")),
            "sent_to_human": to_human,
            "false_alarms": count_incidents(bus),
            "decisions": len(bus.log),
            "ms_per_decision": round(1000 * seconds / max(len(bus.log), 1), 3),
        }
    return results


def print_workload(results):
    print("\nRealistic workload (real BPI purchases, real vendor list):")
    for label, r in results.items():
        share = 100 * r["sent_to_human"] / r["purchases"]
        print(f"  {label:9} paid {r['paid']}/{r['purchases']}, rejected by human {r['rejected_by_human']}, "
              f"sent to human {r['sent_to_human']} ({share:.1f}%), false alarms {r['false_alarms']}, "
              f"{r['decisions']} decisions, {r['ms_per_decision']} ms per decision")

def print_table(rows, normal):
    print(f"{'Attack':22} {'Family':26} {'Compromised':12} {'No guard':10} {'With guard':11} Guard incidents")
    print("-" * 100)
    for row in rows:
        no_guard = "SUCCEEDED" if row["no_guard_succeeded"] else "failed"
        guard = "SUCCEEDED" if row["guard_succeeded"] else "stopped"
        print(f"{row['attack']:22} {row['family']:26} {row['compromised']:12} "
              f"{no_guard:10} {guard:11} {row['guard_incidents']}")

    possible = sum(1 for row in rows if row["no_guard_succeeded"])
    stopped = sum(1 for row in rows if row["no_guard_succeeded"] and not row["guard_succeeded"])
    print(f"\nAttacks that succeed without a guard: {possible}/{len(rows)}")
    print(f"Of those, stopped by the guard:        {stopped}/{possible}")
    for label, (completed, total, incidents) in normal.items():
        print(f"Normal purchases completed ({label}): {completed}/{total}, false alarms: {incidents}")


def save_csv(rows, name):
    """Save the results table as a CSV file in results/."""
    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / f"{name}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


if __name__ == "__main__":
    rows = run_attacks()
    normal = run_normal()
    print_table(rows, normal)
    print("\nResults saved to", save_csv(rows, "attacks_scripted"))
    
    workload = run_workload()
    print_workload(workload)
    workload_rows = []
    for label, r in workload.items():
        row = {"setting": label}
        row.update(r)
        workload_rows.append(row)
    print("Workload results saved to", save_csv(workload_rows, "workload_bpi"))