import json


def _cap(obj, n=1500) -> str:
    s = json.dumps(obj, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + "...[truncated]"


class ToolBox:
    """أدوات قراءة فقط. لا شبكة ولا ملفات. تستلم Findings منقّاة فقط."""
    NAMES = ("get_finding_details", "get_http_evidence", "lookup_cwe",
             "compare_similar", "request_active_verification")

    def __init__(self, findings, cwe_db):
        self.all = list(findings)
        self.by_id = {f.id: f for f in self.all}
        self.cwe = cwe_db
        self.proposals: dict[str, str] = {}

    def run(self, name, args) -> str:
        if name not in self.NAMES:
            return _cap({"error": "unknown tool"})
        try:
            return _cap(getattr(self, name)(**args))
        except TypeError:
            return _cap({"error": "bad arguments"})

    def get_finding_details(self, id):
        f = self.by_id.get(id)
        if not f:
            return {"error": "unknown finding id"}
        return {"id": f.id, "name": f.name, "url": f.url, "method": f.method, "param": f.param,
                "risk": f.zap_risk, "confidence": f.zap_confidence, "cwe_id": f.cwe_id,
                "description": f.description, "solution": f.solution, "evidence": f.evidence,
                "instances": f.instances}

    def get_http_evidence(self, id):
        f = self.by_id.get(id)
        if not f:
            return {"error": "unknown finding id"}
        return {"request": f.request_snippet or "n/a", "response": f.response_snippet or "n/a"}

    def lookup_cwe(self, cwe_id):
        return {"cwe_id": cwe_id, "description": self.cwe.get(str(cwe_id), "not in local database")}

    def compare_similar(self, id):
        f = self.by_id.get(id)
        if not f:
            return {"error": "unknown finding id"}
        others = [g for g in self.all if g.id != f.id]
        return {"instances_in_this_finding": f.instances, "other_urls": f.other_urls,
                "same_name": [{"id": g.id, "url": g.url} for g in others if g.name == f.name][:5],
                "same_cwe": [{"id": g.id, "name": g.name} for g in others
                             if f.cwe_id and g.cwe_id == f.cwe_id][:5],
                "identical_evidence_elsewhere": any(g.evidence and g.evidence == f.evidence for g in others)}

    def request_active_verification(self, id, reason=""):
        if id not in self.by_id:
            return {"error": "unknown finding id"}
        self.proposals[id] = str(reason)[:300]
        return {"status": "proposal recorded. A human must approve. Nothing was executed."}
