# ProtocolGuard

**Execution guards for LLM multi-agent workflows.** Every message and action between agents is checked at runtime against an explicit interaction protocol (roles, states, value conditions, actions), tested on real purchase data (BPI Challenge 2019) and local LLM agents.


📄 Technical report (version 1, ongoing project): [docs/ProtocolGuard_Technical_Report.pdf](docs/ProtocolGuard_Technical_Report.pdf)

## Why

In multi-agent systems, risk often lies in the *interaction*: an instruction outside someone's role, a message at the wrong moment, a step in the wrong state. An LLM agent that reads untrusted text (here, a vendor's quote) can be manipulated by prompt injection. ProtocolGuard does not try to detect the attack in the text. It checks whether the resulting behaviour is permitted, so it works regardless of the model behind the agent.

## How it works

```
requester → procurement (LLM, reads untrusted quotes) → approver → human_manager → payment → bank
                         every message and action passes through
                 MessageBus → ProtocolGuard (ALLOW / BLOCK / ESCALATE) → delivery
```

- **Protocol** (`protocol/purchase_protocol.yaml`): roles, states, 7 messages, 1 action, 6 condition types, escalation, trusted registries (1,975 real vendors; recorded offers).
- **Loader**: design-time checking; the system refuses to start on a broken protocol (fail closed).
- **Guard**: deny by default; the bus writes sender and message ID (no impersonation); remembers only required fields (no memory poisoning); re-checks payments at the point of action; every refusal gets an incident ID and a reason.
- **Bus and sandbox**: agents never hold tools (complete mediation); a fake bank ledger is the ground truth; a no-guard baseline for comparison.

## Key results

| Experiment | Without guard | With guard |
|---|---|---|
| 7 scripted attacks (one compromised agent each) | 7/7 succeed | 6/7 stopped (purchase splitting is a known cross-case gap) |
| 1,000 real BPI purchases | — | 0 false alarms, identical outcomes |
| 60 attacks hidden among 1,000 real purchases | 60/60 succeed | 0/60 succeed, 60/60 detected, 0 false alarms on 940 legitimate |
| Prompt injection, Qwen 3.5 9B (180 injected runs) | 38% harmful | 6% harmful |
| Prompt injection, Llama 3.1 8B (180 injected runs) | 36% harmful | 17% harmful |

For both models, every out-of-role action and every invented value was blocked. All remaining harm is **semantic steering**: choosing a valid but non-cheapest offer, which no message-level rule can detect. This motivates learned and hybrid guards.

## Quick start

```
python -m venv .venv
.venv\Scripts\activate            # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
python -m pytest                  # 24 tests
```

**Data.** Download the BPI Challenge 2019 log and place a CSV export at `data/bpi2019/BPI_Challenge_2019.csv.gz`. The CSV export used here is the unmodified copy in the release of [jadzoghaib/processlens](https://github.com/jadzoghaib/processlens/releases) (SHA-256 `2a6fae0e…238a7`). Please cite the official dataset. Then:

```
python -m bpi.explore             # sanity check: 1,595,923 events, 251,734 cases
python -m bpi.make_vendors        # builds data/vendors_bpi.yaml (1,975 vendors)
python -m run_experiment          # scripted attacks + 1,000-purchase workload
python -m run_experiment mixed    # attacks hidden among real purchases
```

**LLM experiments** need [Ollama](https://ollama.com) and the models `qwen3.5:9b` and `llama3.1:8b`:

```
python -m run_experiment llm      # Qwen 3.5 9B
python -m run_experiment llm llama
```

## Repository layout

```
protocol/   protocol file and loader          bus/      message bus and fake bank
guards/     ProtocolGuard and NoGuard          agents/   scripted and LLM agents
attacks/    attack scenarios and injections    bpi/      BPI loading, vendors, workload
tests/      automated tests                    results/  CSV result tables
```

## Limitations

A sandbox with one workflow and a small protocol; the human and payments are simulated; the attacks and the protocol were designed by the same author; two local models (a Gemini run was rate-limited). See the report for details.

## Data

B. F. van Dongen, *BPI Challenge 2019*, 4TU.ResearchData, doi:10.4121/uuid:d06aff4b-79f0-45e6-8ec8-e19730c248f1. Neither raw nor derived data is redistributed in this repository.

## Author

Haneen Kodamy · [GitHub](https://github.com/HaninKodamy) · [ORCID](https://orcid.org/0009-0007-5111-455X)