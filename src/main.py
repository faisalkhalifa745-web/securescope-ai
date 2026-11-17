import json

import typer
import yaml
from dotenv import load_dotenv
from rich.console import Console

import dvwa
from audit import AuditLog
from llm_client import GroqClient
from orchestrator import Orchestrator
from policy import PolicyEngine
from report import build_report
from review_cli import ask_phrase, auto_review, review
from scope import ScopeGuard
from state import StateStore
from zap_client import ZapClient

app = typer.Typer(help="SecureScope AI")
console = Console()


def _build(auto: bool, ajax: bool):
    load_dotenv()
    cfg = yaml.safe_load(open("config.yaml", encoding="utf-8"))
    audit = AuditLog(cfg["paths"]["audit"])
    scope = ScopeGuard.from_config("config.yaml", audit=audit)
    policy = PolicyEngine(scope, audit)
    z, l, p = cfg["zap"], cfg["llm"], cfg["paths"]
    zap = ZapClient(policy, audit, host=z["host"], port=z["port"], spider_timeout=z["spider_timeout"],
                    passive_timeout=z["passive_timeout"], active_timeout=z["active_timeout"],
                    use_ajax=ajax or z.get("use_ajax_spider", False), raw_path=p["raw_alerts"])
    llm = GroqClient(min_interval=l["min_interval_sec"])
    orch = Orchestrator(
        scope=scope, policy=policy, audit=audit, zap=zap, llm=llm,
        review_fn=auto_review if auto else review,
        approve_fn=(lambda url, reason: "") if auto else ask_phrase,
        report_fn=lambda items, target: build_report(items, target, audit, out_dir=p["reports"]),
        store=StateStore(p["state"]), cwe_db=json.load(open(p["cwe"], encoding="utf-8")),
        max_steps=l["max_steps"], max_findings=l["max_findings"], findings_path=p["findings"])
    return orch, zap, llm, scope, policy, audit


@app.command()
def check():
    """يتأكد أن ZAP و Groq يشتغلان."""
    _, zap, llm, *_ = _build(True, False)
    console.print("ZAP version:", zap.version())
    console.print("Groq OK:", llm.ping())


@app.command()
def scan(target: str = "http://127.0.0.1:3000", auto: bool = False, ajax: bool = False):
    """auto=مراجعة تلقائية للتجارب (بدون Active Scan). بدونه تظهر واجهة المراجع."""
    orch, zap, _, scope, policy, _ = _build(auto, ajax)
    t = scope.validate(target)
    excludes = ()
    if t.name == "DVWA":
        zap.set_auth_cookie(dvwa.login(f"http://{t.host}:{t.port}", policy))
        excludes = (r".*logout.*", r".*setup\.php.*")
    try:
        path = orch.run(target, excludes=excludes)
    finally:
        zap.clear_auth_cookie()
    console.print(f"[green]Report:[/green] {path}")


@app.command("verify-audit")
def verify_audit():
    _, _, _, _, _, audit = _build(True, False)
    console.print("[green]Audit chain OK[/green]" if audit.verify() else "[red]TAMPERED![/red]")


if __name__ == "__main__":
    app()
