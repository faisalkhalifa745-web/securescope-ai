import json

from pydantic import ValidationError

import prompts
from models import Assessment

FINAL_FIELDS = ("likelihood", "false_positive_suspected", "reasoning", "remediation",
                "needs_active_verification", "verification_reason")


def _fallback(f, used, steps, why):
    lik = "medium" if f.zap_risk in ("Medium", "High") else "low"
    return Assessment(finding_id=f.id, likelihood=lik, false_positive_suspected=False,
                      reasoning=f"LLM analysis unavailable ({why}); based on ZAP rating only.",
                      remediation=(f.solution[:300] or "See ZAP guidance."),
                      steps_used=steps, tools_used=used, fallback=True)


def assess(f, toolbox, llm, audit=None, max_steps=5) -> Assessment:
    """Bounded loop: observe -> reason -> choose tool -> execute -> update -> repeat/finalize."""
    system = prompts.system_prompt(max_steps)
    msgs = [{"role": "user", "content": prompts.first_message(f)}]
    used: list[str] = []
    for step in range(1, max_steps + 1):
        if step == max_steps:
            msgs.append({"role": "user", "content": "LAST step: you MUST reply with action finalize_assessment now."})
        try:
            reply = llm.chat_json(system, msgs)
        except Exception as e:
            if audit:
                audit.log("agent_llm_error", finding=f.id, error=str(e)[:200])
            return _fallback(f, used, step - 1, "LLM error")
        if not isinstance(reply, dict):
            reply = {}
        action = reply.get("action")
        args = reply.get("args") if isinstance(reply.get("args"), dict) else {}
        if audit:
            audit.log("agent_step", finding=f.id, step=step, action=str(action)[:40])
        msgs.append({"role": "assistant", "content": json.dumps(reply, ensure_ascii=False)[:1200]})

        if action == "finalize_assessment":
            data = {k: args[k] for k in FINAL_FIELDS if k in args}
            if isinstance(data.get("likelihood"), str):
                data["likelihood"] = data["likelihood"].lower()
            try:
                a = Assessment(finding_id=f.id, steps_used=step, tools_used=used, **data)
            except ValidationError as e:
                msgs.append({"role": "user", "content": "finalize_assessment args invalid: "
                             + str(e.errors()[0]["msg"])[:150] + ". Fix and finalize again."})
                continue
            if f.id in toolbox.proposals:
                a.needs_active_verification = True
                a.verification_reason = a.verification_reason or toolbox.proposals[f.id]
            return a

        if action in toolbox.NAMES:
            used.append(action)
            result = toolbox.run(action, args)
            msgs.append({"role": "user", "content": f"<data>{result}</data>\nNext action? (JSON)"})
        else:
            msgs.append({"role": "user", "content": f"Unknown action. Allowed: {', '.join(toolbox.NAMES)}, finalize_assessment."})
    return _fallback(f, used, max_steps, "step budget exhausted")
