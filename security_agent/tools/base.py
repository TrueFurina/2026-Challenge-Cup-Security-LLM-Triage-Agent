class Tool:
    """工具基类。

    `requires` 是该工具**调用必需的入参键**，必须与 `run()` 实际读取的键
    逐项一致。它是单一事实源：

    - MCP 层据此生成 `tools/list` 的 `inputSchema.required`（客户端按声明传参）；
    - MCP 层据此在调用失败时给出**点名缺哪个参数**的可操作提示。

    2026-10-14 新增。此前 `required` 对所有工具硬编码为 `["event"]`，
    而实测 11 个工具中 6 个只传 event 必然失败（`analysis` / `*_observation`
    缺失）——即**声明与实现不符**，任何遵循声明的客户端都调不动这些工具；
    同时失败提示把缺 `command` 也一并归因为"缺上游阶段参数"，把调用方引向
    错误方向。声明与实现必须同源，故收敛到这个字段。
    """

    name = ""
    #: 调用本工具必需的入参键（含 `event`，如需要）。
    requires: tuple[str, ...] = ()

    def run(self, **kwargs):
        raise NotImplementedError
