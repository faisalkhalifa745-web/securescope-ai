import json
import os
import re
import time

from groq import APIConnectionError, APIStatusError, Groq, RateLimitError


def _extract_json(text: str) -> dict:
    text = (text or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise ValueError("no JSON object in reply")
        return json.loads(m.group(0))


class GroqClient:
    def __init__(self, model=None, fallback_model=None, temperature=0.1, max_tokens=700,
                 min_interval=2.0, max_attempts=6):
        key = os.environ.get("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY is missing in .env")
        self.client = Groq(api_key=key, max_retries=0)
        self.model = model or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.fallback_model = fallback_model or os.getenv("GROQ_FALLBACK_MODEL", "llama-3.1-8b-instant")
        self.temperature, self.max_tokens = temperature, max_tokens
        self.min_interval, self.max_attempts = min_interval, max_attempts
        self._last = 0.0
        self.calls = 0

    def _pace(self):
        gap = self.min_interval - (time.time() - self._last)
        if gap > 0:
            time.sleep(gap)

    def chat_json(self, system: str, messages: list[dict]) -> dict:
        model, last = self.model, None
        for attempt in range(self.max_attempts):
            self._pace()
            try:
                r = self.client.chat.completions.create(
                    model=model, temperature=self.temperature, max_tokens=self.max_tokens,
                    response_format={"type": "json_object"},
                    messages=[{"role": "system", "content": system}] + messages)
                self._last = time.time()
                self.calls += 1
                return _extract_json(r.choices[0].message.content)
            except RateLimitError as e:
                last = e
                if attempt >= 1:
                    model = self.fallback_model
                time.sleep(min(30, 2 ** (attempt + 1)))
            except APIConnectionError as e:
                last = e
                time.sleep(2 ** attempt)
            except APIStatusError as e:
                if e.status_code >= 500:
                    last = e
                    time.sleep(2 ** attempt)
                else:
                    raise RuntimeError(f"Groq error {e.status_code}: تحقق من المفتاح/اسم النموذج") from e
            except ValueError as e:
                last = e
                messages = messages + [{"role": "user",
                                        "content": "Your last reply was not valid JSON. Reply with ONE valid JSON object only."}]
        raise RuntimeError(f"Groq failed after {self.max_attempts} attempts: {last}")

    def ping(self) -> bool:
        return self.chat_json('Reply with JSON {"ok": true}', [{"role": "user", "content": "ping, answer in JSON"}]).get("ok") is True
