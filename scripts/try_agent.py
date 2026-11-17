import json
import sys
sys.path.insert(0, "src")
from dotenv import load_dotenv
load_dotenv()
from agent import assess
from llm_client import GroqClient
from models import Finding
from tools import ToolBox

fs = [
    Finding(id="F001", name="Missing Anti-clickjacking Header", url="http://127.0.0.1:3000/",
            zap_risk="Medium", cwe_id=1021, description="X-Frame-Options header not set"),
    Finding(id="F002", name="Cookie without SameSite", url="http://127.0.0.1:3000/",
            zap_risk="Low", cwe_id=1275, param="sid"),
    Finding(id="F003", name="Server leaks version", url="http://127.0.0.1:3000/",
            zap_risk="Low", cwe_id=200, evidence="X-Powered-By: Express"),
]
tb = ToolBox(fs, json.load(open("data/cwe.json", encoding="utf-8")))
llm = GroqClient()
for f in fs:
    print(assess(f, tb, llm, max_steps=5).model_dump_json(indent=2))
