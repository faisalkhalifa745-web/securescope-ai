from agent import assess
from models import Finding
from tools import ToolBox


class FakeLLM:
    def __init__(self, replies):
        self.replies = list(replies)

    def chat_json(self, system, messages):
        return self.replies.pop(0)


def finding():
    return Finding(id="F001", name="Missing CSP", url="http://127.0.0.1:3000", zap_risk="Medium", cwe_id=693)


def final(**kw):
    args = {"likelihood": "medium", "false_positive_suspected": False, "reasoning": "r", "remediation": "fix"}
    args.update(kw)
    return {"action": "finalize_assessment", "args": args}


def test_uses_tools_then_finalizes():
    f = finding()
    llm = FakeLLM([{"action": "lookup_cwe", "args": {"cwe_id": 693}},
                   {"action": "get_http_evidence", "args": {"id": "F001"}}, final()])
    a = assess(f, ToolBox([f], {"693": "x"}), llm)
    assert a.steps_used == 3 and a.tools_used == ["lookup_cwe", "get_http_evidence"] and not a.fallback


def test_invalid_actions_fall_back():
    f = finding()
    a = assess(f, ToolBox([f], {}), FakeLLM([{"action": "run_scan"}] * 5), max_steps=5)
    assert a.fallback and a.likelihood == "medium"


def test_bad_final_is_retried():
    f = finding()
    llm = FakeLLM([final(likelihood="very-high"), final(likelihood="HIGH")])
    assert assess(f, ToolBox([f], {}), llm).likelihood == "high"


def test_active_verification_is_only_a_proposal():
    f = finding()
    tb = ToolBox([f], {})
    llm = FakeLLM([{"action": "request_active_verification", "args": {"id": "F001", "reason": "check headers"}}, final()])
    a = assess(f, tb, llm)
    assert a.needs_active_verification and tb.proposals["F001"] == "check headers"
