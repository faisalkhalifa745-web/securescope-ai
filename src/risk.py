BASE = {"Informational": 0.5, "Low": 2.0, "Medium": 5.0, "High": 8.0}
LIKELIHOOD = {"low": 0.6, "medium": 1.0, "high": 1.25}
ZAP_CONF = {"False Positive": 0.0, "Low": 0.7, "Medium": 0.9, "High": 1.0,
            "Confirmed": 1.0, "User Confirmed": 1.0}


def score(f, a) -> float:
    """حتمي 100%: لا LLM هنا. الـ LLM يعطي likelihood فقط."""
    s = BASE[f.zap_risk] * LIKELIHOOD[a.likelihood] * ZAP_CONF.get(f.zap_confidence, 0.9)
    if a.false_positive_suspected:
        s *= 0.3
    return round(min(10.0, max(0.0, s)), 1)


def label(s: float) -> str:
    return "Critical" if s >= 8 else "High" if s >= 6 else "Medium" if s >= 3 else "Low" if s >= 1 else "Info"
