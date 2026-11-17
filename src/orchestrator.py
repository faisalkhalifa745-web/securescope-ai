import json
from enum import Enum
from pathlib import Path

from agent import assess
from models import ReviewItem
from normalizer import normalize
from policy import ApprovalDenied
from risk import score
from sanitizer import sanitize_finding
from scope import ScopeViolation
from tools import ToolBox


class S(str, Enum):
    INIT = "INIT"
    SCOPE_OK = "SCOPE_OK"
    PASSIVE_SCAN = "PASSIVE_SCAN"
    NORMALIZE = "NORMALIZE"
    ANALYZE = "ANALYZE"
    REVIEW = "REVIEW"
    ACTIVE_APPROVAL = "ACTIVE_APPROVAL"
    REPORT = "REPORT"
    DONE = "DONE"
    FAILED = "FAILED"


ALLOWED = {
    S.INIT: {S.SCOPE_OK}, S.SCOPE_OK: {S.PASSIVE_SCAN}, S.PASSIVE_SCAN: {S.NORMALIZE},
    S.NORMALIZE: {S.ANALYZE}, S.ANALYZE: {S.REVIEW}, S.REVIEW: {S.ACTIVE_APPROVAL, S.REPORT},
    S.ACTIVE_APPROVAL: {S.REPORT}, S.REPORT: {S.DONE},
}


class Orchestrator:
    def __init__(self, *, scope, policy, audit, zap, llm, review_fn, approve_fn, report_fn,
                 store, cwe_db, max_steps=5, max_findings=15, findings_path="data/findings.json"):
        self.scope, self.policy, self.audit, self.zap, self.llm = scope, policy, audit, zap, llm
        self.review_fn, self.approve_fn, self.report_fn = review_fn, approve_fn, report_fn
        self.store, self.cwe_db = store, cwe_db
        self.max_steps, self.max_findings, self.findings_path = max_steps, max_findings, findings_path
        self.state, self._next_id = S.INIT, 1

    def _go(self, new: S):
        if new != S.FAILED and new not in ALLOWED.get(self.state, set()):
            raise RuntimeError(f"illegal transition {self.state} -> {new}")
        self.audit.log("state", frm=self.state.value, to=new.value)
        self.state = new
        self.store.save(state=new.value)

    def _analyze(self, findings) -> list[ReviewItem]:
        safe = [sanitize_finding(f) for f in findings][: self.max_findings]
        tb = ToolBox(safe, self.cwe_db)
        items = []
        for f in safe:
            a = assess(f, tb, self.llm, self.audit, self.max_steps)
            items.append(ReviewItem(finding=f, assessment=a, score=score(f, a)))
        return items

    def _apply(self, items, decisions):
        by = {i.finding.id: i for i in items}
        for d in decisions:
            it = by.get(d.finding_id)
            if not it:
                continue
            if d.final_likelihood:
                it.assessment.likelihood = d.final_likelihood
                it.score = score(it.finding, it.assessment)
            it.decision = d
            self.audit.log("human_decision", finding=d.finding_id, decision=d.decision,
                           final_likelihood=d.final_likelihood, note=d.note[:200],
                           active_requested=d.approve_active_verification)

    def _active_phase(self, wanted, orig, target_name):
        new_items = []
        for it in wanted:
            url = orig[it.finding.id]
            phrase = self.approve_fn(url, it.assessment.verification_reason)
            try:
                approval = self.policy.request_active_approval(url, phrase)
                raw = self.zap.active_scan(url, approval)
            except (ApprovalDenied, ScopeViolation):
                continue
            fresh = normalize(raw, target_name, self.zap.fetch_message, source="active", start=self._next_id)
            self._next_id += len(fresh)
            if fresh:
                extra = self._analyze(fresh)
                self._apply(extra, self.review_fn(extra))
                new_items += extra
        return new_items

    def _save(self, items):
        Path(self.findings_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.findings_path).write_text(
            json.dumps([i.finding.model_dump() for i in items], ensure_ascii=False, indent=2), encoding="utf-8")
        self.store.save(items=[i.model_dump() for i in items])

    def run(self, target_url, excludes=()):
        try:
            target = self.scope.validate(target_url)
            self._go(S.SCOPE_OK)
            self._go(S.PASSIVE_SCAN)
            raw = self.zap.passive_scan(target_url, excludes=excludes)
            self._go(S.NORMALIZE)
            findings = normalize(raw, target.name, self.zap.fetch_message)
            self._next_id = len(findings) + 1
            self.audit.log("normalized", raw_alerts=len(raw), findings=len(findings))
            orig = {f.id: f.url for f in findings}
            self._go(S.ANALYZE)
            items = self._analyze(findings)
            self._go(S.REVIEW)
            self._apply(items, self.review_fn(items))
            wanted = [i for i in items if i.decision and i.decision.approve_active_verification]
            if wanted:
                self._go(S.ACTIVE_APPROVAL)
                items += self._active_phase(wanted, orig, target.name)
            self._go(S.REPORT)
            path = self.report_fn(items, target.name)
            self._save(items)
            self._go(S.DONE)
            return path
        except Exception as e:
            self.audit.log("run_failed", error=str(e)[:200])
            if self.state not in (S.DONE, S.FAILED):
                self._go(S.FAILED)
            raise
