import json
from pathlib import Path

from security_agent.agent.models import SecurityEvent


class EventIntakeService:
    def __init__(self, events: list[SecurityEvent]):
        self._events = {event.id: event for event in events}

    @classmethod
    def default(cls) -> "EventIntakeService":
        data_path = Path(__file__).resolve().parent.parent / "data" / "alerts.json"
        rows = json.loads(data_path.read_text(encoding="utf-8"))
        return cls(events=[SecurityEvent(**row) for row in rows])

    def list_events(self) -> list[SecurityEvent]:
        return list(self._events.values())

    def get_event(self, event_id: str) -> SecurityEvent:
        if event_id not in self._events:
            raise ValueError(f"Unknown event_id: {event_id}")
        return self._events[event_id]

    def build_submission_event(self, payload: str, source_type: str) -> SecurityEvent:
        if source_type == "json":
            return self._build_from_json(payload)
        if source_type == "log":
            return self._build_from_log(payload)
        raise ValueError(f"Unsupported source_type: {source_type}")

    def _build_from_json(self, payload: str) -> SecurityEvent:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError(f"事件 JSON 解析失败: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("事件 JSON 必须是对象结构")

        raw_log = str(data.get("raw_log", ""))
        process = str(data.get("process", "unknown.exe"))
        title = str(data.get("title", "上传的安全事件"))
        behavior = str(data.get("behavior", raw_log[:120] or "待分析"))
        severity = str(data.get("severity", "medium"))
        source_ip = str(data.get("source_ip", ""))
        host = str(data.get("host", "UPLOAD-HOST"))
        user = str(data.get("user", "unknown.user"))
        destination_ip = str(data.get("destination_ip", ""))
        destination_domain = str(data.get("destination_domain", ""))
        change_ticket = str(data.get("change_ticket", ""))
        tags = data.get("tags", [])
        if not isinstance(tags, list):
            tags = []

        return SecurityEvent(
            id="UPLOAD-JSON",
            title=title,
            severity=severity,
            source_ip=source_ip,
            host=host,
            user=user,
            process=process,
            behavior=behavior,
            raw_log=raw_log,
            destination_ip=destination_ip,
            destination_domain=destination_domain,
            change_ticket=change_ticket,
            tags=[str(item) for item in tags],
        )

    def _build_from_log(self, payload: str) -> SecurityEvent:
        raw_log = payload.strip()
        if not raw_log:
            raise ValueError("日志文本不能为空")

        lowered = raw_log.lower()
        process = "unknown.exe"
        if "powershell" in lowered:
            process = "powershell.exe"
        elif "browser" in lowered or "dns" in lowered:
            process = "browser.exe"
        elif "login" in lowered:
            process = "login-process"

        title = "上传日志触发的待研判安全事件"
        behavior = raw_log[:160]
        if "encodedcommand" in lowered or "downloadstring" in lowered:
            title = "上传日志显示疑似脚本下载执行"
        elif "maintenance" in lowered or "whitelist" in lowered:
            title = "上传日志显示可能与运维白名单相关"
        elif "dns" in lowered or "outbound" in lowered:
            title = "上传日志显示异常外联行为"

        destination_domain = ""
        for token in raw_log.replace(",", " ").split():
            if "." in token and not token.endswith(".exe") and len(token) > 4:
                destination_domain = token.strip(" ;,")
                break

        return SecurityEvent(
            id="UPLOAD-LOG",
            title=title,
            severity="medium",
            source_ip="",
            host="UPLOAD-HOST",
            user="uploaded.user",
            process=process,
            behavior=behavior,
            raw_log=raw_log,
            destination_domain=destination_domain,
        )
