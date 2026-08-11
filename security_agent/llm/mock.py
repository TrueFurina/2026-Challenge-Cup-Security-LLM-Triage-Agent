from security_agent.llm.base import LLMBase


class MockLLM(LLMBase):
    def summarize(self, event, analysis, knowledge_items, plan):
        evidence = list(analysis["evidence"])
        evidence.append(f"执行计划: {' -> '.join(plan)}")

        recommendations = list(analysis["recommendations"])
        if analysis["risk_level"] in {"high", "critical"}:
            recommendations.insert(0, "立即通知安全运营人员进行复核")

        return {
            "verdict": analysis["verdict"],
            "risk_level": analysis["risk_level"],
            "is_false_positive": analysis["is_false_positive"],
            "evidence": evidence,
            "recommendations": recommendations,
        }
