import pytest

from models import Assessment, Finding
from risk import label, score


def mk(risk, conf, lik, fp=False):
    f = Finding(id="F1", name="n", url="http://127.0.0.1:3000", zap_risk=risk, zap_confidence=conf)
    a = Assessment(finding_id="F1", likelihood=lik, false_positive_suspected=fp, reasoning="r", remediation="x")
    return f, a


@pytest.mark.parametrize("risk,conf,lik,fp,expected", [
    ("High", "High", "medium", False, 8.0),
    ("High", "High", "high", False, 10.0),          # سقف 10
    ("Medium", "Medium", "low", False, 2.7),
    ("Medium", "High", "medium", True, 1.5),        # مشتبه false positive
    ("Informational", "Low", "low", False, 0.2),
])
def test_score_table(risk, conf, lik, fp, expected):
    assert score(*mk(risk, conf, lik, fp)) == pytest.approx(expected, abs=0.05)


def test_labels():
    assert label(9) == "Critical" and label(4) == "Medium" and label(0.2) == "Info"
