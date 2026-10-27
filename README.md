# ProtocolGuard

Explicit and Learned Interaction Protocols as Execution Guards for LLM Multi-Agent Workflows.

A sandboxed purchase-to-pay workflow run by LLM agents, where every message between agents passes through an execution guard that checks it against an interaction protocol. We attack the workflow and measure how well hand-written, learned and hybrid guards stop unsafe interactions without blocking legitimate work or overloading the human approver.