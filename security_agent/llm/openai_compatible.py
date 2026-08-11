import json
from urllib import request

from security_agent.llm.base import LLMBase
from security_agent.prompts.templates import (
    TRIAGE_SYSTEM_PROMPT,
    build_triage_user_prompt,
)


class OpenAICompatibleLLM(LLMBase):
    def __init__(self, base_url: str, api_key: str, model: str, timeout_seconds: int):
        if not api_key:
            raise ValueError(
                "SECURITY_AGENT_LLM_API_KEY is required when SECURITY_AGENT_USE_REAL_LLM=1"
            )
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def summarize(self, event, analysis, knowledge_items, plan):
        prompt = build_triage_user_prompt(event, analysis, knowledge_items, plan)
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": TRIAGE_SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "temperature": 0.2,
        }
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.base_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with request.urlopen(req, timeout=self.timeout_seconds) as response:
            raw = json.loads(response.read().decode("utf-8"))
        content = raw["choices"][0]["message"]["content"]
        return self._extract_json(content)

    def _extract_json(self, content: str) -> dict:
        content = content.strip()
        if content.startswith("```"):
            lines = [line for line in content.splitlines() if not line.startswith("```")]
            content = "\n".join(lines).strip()
        return json.loads(content)
