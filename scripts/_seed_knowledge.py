"""扩充知识库到 50+ 条"""
import json

data = json.loads(open('security_agent/data/knowledge.json', encoding='utf-8').read())
existing = {d['title'] for d in data}

new = [
    {'title': 'ATT&CK 持久化：启动项服务注册（T1547）', 'content': '攻击者通过注册表启动项、计划任务、系统服务实现持久化。', 'tags': ['persistence', 'startup'], 'category': 'attack', 'attck_ids': ['T1547', 'T1037'], 'cve_ids': []},
    {'title': 'ATT&CK 提权：系统漏洞利用（T1068）', 'content': '攻击者利用操作系统或服务漏洞获取更高权限。', 'tags': ['privilege-escalation', 'kernel'], 'category': 'attack', 'attck_ids': ['T1068', 'T1055'], 'cve_ids': ['CVE-2021-3156']},
    {'title': 'ATT&CK 防御规避：进程注入（T1055）', 'content': '攻击者将恶意代码注入合法进程执行。', 'tags': ['process-injection', 'evasion'], 'category': 'attack', 'attck_ids': ['T1055', 'T1027'], 'cve_ids': []},
    {'title': 'ATT&CK 发现：网络扫描（T1046）', 'content': '攻击者扫描内网发现开放端口和服务。', 'tags': ['network-scan', 'discovery'], 'category': 'attack', 'attck_ids': ['T1046', 'T1018'], 'cve_ids': []},
    {'title': 'ATT&CK C2：DNS 隧道信标（T1071.004）', 'content': '攻击者通过 DNS 隧道与 C2 通信。', 'tags': ['dns-tunnel', 'beacon', 'c2'], 'category': 'attack', 'attck_ids': ['T1071.004', 'T1568'], 'cve_ids': []},
    {'title': 'ATT&CK 数据影响：加密删除（T1486）', 'content': '攻击者加密或删除数据造成破坏。', 'tags': ['ransomware', 'impact'], 'category': 'attack', 'attck_ids': ['T1486', 'T1490'], 'cve_ids': []},
    {'title': 'Web 安全：SQL 注入', 'content': '攻击者通过 SQL 注入获取数据库访问。', 'tags': ['sqli', 'web'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：XSS 跨站脚本', 'content': '攻击者注入恶意脚本到网页。', 'tags': ['xss', 'web'], 'category': 'attack', 'attck_ids': ['T1059.007'], 'cve_ids': []},
    {'title': 'Web 安全：SSRF 服务端请求伪造', 'content': '攻击者构造请求让服务器访问内网。', 'tags': ['ssrf', 'web'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：SSTI 服务端模板注入', 'content': '攻击者注入模板代码执行命令。', 'tags': ['ssti', 'web'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：反序列化漏洞', 'content': '攻击者利用反序列化执行任意代码。', 'tags': ['deserialization', 'web'], 'category': 'attack', 'attck_ids': ['T1204.002'], 'cve_ids': ['CVE-2017-5638']},
    {'title': 'Web 安全：文件上传漏洞', 'content': '攻击者上传 webshell 或恶意文件。', 'tags': ['file-upload', 'webshell'], 'category': 'attack', 'attck_ids': ['T1505.003'], 'cve_ids': []},
    {'title': 'Web 安全：路径穿越', 'content': '攻击者通过 ../ 访问受限文件。', 'tags': ['path-traversal', 'lfi'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': ['CVE-2021-41773']},
    {'title': 'Web 安全：弱口令默认凭证', 'content': '攻击者利用默认或弱口令登录。', 'tags': ['brute-force', 'weak-password'], 'category': 'attack', 'attck_ids': ['T1110', 'T1078'], 'cve_ids': []},
    {'title': 'Web 安全：API 越权 IDOR', 'content': '攻击者修改参数访问他人数据。', 'tags': ['idor', 'broken-access-control'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：CSRF 跨站请求伪造', 'content': '攻击者伪造用户请求执行操作。', 'tags': ['csrf', 'web'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：JWT 伪造', 'content': '攻击者伪造 JWT Token 绕过认证。', 'tags': ['jwt', 'authentication'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：点击劫持', 'content': '攻击者通过 iframe 诱导用户点击。', 'tags': ['clickjacking', 'web'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：信息泄露', 'content': '攻击者通过 .git、.bak、.env 获取敏感信息。', 'tags': ['information-disclosure', 'web'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：供应链攻击', 'content': '攻击者通过第三方库注入恶意代码。', 'tags': ['supply-chain', 'web'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：AI Agent 提示注入', 'content': '攻击者通过提示注入操纵 LLM。', 'tags': ['prompt-injection', 'llm-security'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'Web 安全：MCP 工具调用滥用', 'content': '攻击者滥用 MCP 工具执行非预期操作。', 'tags': ['mcp-abuse', 'tool-misuse'], 'category': 'attack', 'attck_ids': ['T1190'], 'cve_ids': []},
    {'title': 'CVE-2021-3156：Sudo 提权', 'content': 'Sudo 堆缓冲区溢出导致提权。', 'tags': ['sudo', 'privilege-escalation'], 'category': 'attack', 'attck_ids': ['T1068'], 'cve_ids': ['CVE-2021-3156']},
    {'title': 'CVE-2022-0847：Dirty Pipe', 'content': 'Linux 内核管道漏洞导致提权。', 'tags': ['linux', 'kernel'], 'category': 'attack', 'attck_ids': ['T1068'], 'cve_ids': ['CVE-2022-0847']},
]

added = [d for d in new if d['title'] not in existing]
data.extend(added)
with open('security_agent/data/knowledge.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print(f'扩充完成: {len(data)} 条（新增 {len(added)} 条）')
print(f'含 attck_ids: {sum(1 for d in data if d.get("attck_ids"))}')
print(f'含 cve_ids: {sum(1 for d in data if d.get("cve_ids"))}')
