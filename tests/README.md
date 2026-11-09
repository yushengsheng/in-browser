# 项目自检

本地创建新增`test_window_creation.py`（幂等、逐项代理、取消恢复、编译和旧窗口隔离）、`test_ssh_proxy.py`（真实回环SSH认证/主机密钥/转发/检测进程）及`test_dynamic_proxy.py`（提取格式、超时、失败不直连）。前端回归覆盖新建表单、结果不确定重试、任务恢复、取消和迟到响应；真实专项见`docs/本地窗口创建.md`。

在项目目录执行：

```powershell
.\runtime\python\python.exe -B .\tools\check_project.py
```

默认检查 app 程序 Python/PYW 语法、JavaScript 语法、项目契约及 10 个已审查的合成数据测试。Python 使用便携运行时，缺失时使用当前解释器。Node.js 可用时额外运行 `tests/frontend-state.test.js`；Node.js 缺失会明确记为 skipped，不影响 Python 测试。

```powershell
.\runtime\python\python.exe -B .\tools\check_project.py --static-only
.\runtime\python\python.exe -B .\tools\check_project.py --unit-only
.\runtime\python\python.exe -B .\tools\check_project.py --report "$PWD\analysis\reports\my-check.json"
.\runtime\python\python.exe -B .\tests\test_project_contracts.py
.\runtime\python\python.exe -B .\tests\test_installation_inspector.py
.\runtime\python\python.exe -B .\tests\test_proxy_deadline.py
.\runtime\python\python.exe -B .\tests\test_removed_features.py
```

`--report` 必须为绝对路径；默认报告为 `analysis/reports/project-check-latest.json`。仅打印 passed / failed / skipped 数量，失败返回退出码 1。详细失败输出先在本机脱敏，再写入指定 JSON；单项执行超时为 120 秒，随后清理本次进程树。每路输出超过 1 MiB 也会终止并记为失败，报告记录日志截断。测试内部 JSON 的 `success:false` 或失败的 `checks` 也会计为失败，不会因进程退出码 0 被当作通过。

固定 Python 测试白名单：

- portable-vault-tests.py、portable-browser-tests.py、portable-state-tests.py
- signature-guard-tests.py、local-engine-tests.py、local-signer-tests.py
- sync-source-tests.py（不带 `--smoke`）、fingerprint-continuity-tests.py
- conservative-policy-tests.py、proxy-runtime-protocol-tests.py

这些测试仅使用临时合成资料；协议测试只连接本机回环服务。自检不启动浏览器，不访问真实账号目录，不运行 analysis 中其他历史脚本，不调用在线测试。子进程隔离 APPDATA、LOCALAPPDATA、用户目录与 Python 用户配置，并使用受控 PATH。app/data 的用户资料、缓存和备份不扫描；仅固定的两个打包 resources JavaScript 文件参与语法检查。语法检查使用 `compile`，不导入应用、不写 pyc。历史测试自写的两个固定报告被抑制，自检仅更新 `--report` 指定文件。

自检验证代码和合成边界；真实浏览器、真实代理、用户资料迁移及打包完整性需要另外按明确场景验证。某些旧测试与当前环境不兼容时会如实失败并记录，不会自动跳过或改写应用行为。

`test_proxy_deadline.py`使用本机模拟代理，验证备用站点与慢滴流共用10秒预算、超时进程退出、迟到结果拒绝，以及认证失败/重定向不直连。`test_removed_features.py`验证已删除动作和无ID保存被拒绝，同时保护已有编辑、来源导入去重、旧目录迁移和失败回滚；二者均纳入默认自检。

以下也已纳入默认自检：`test_source_preparation.py`用模拟API核对新来源、缓存身份/状态及发布前准备；`test_sync_reliability.py`用临时SQLite/资料验证10000来源分9999+1、唯一绑定、取消重启、五阶段强退与认证恢复；`test_batch_status.py`用合成进程验证万条状态只扫描一次并集中保存。均不读取真实资料或联网；目录junction与真实vault测试只作用于自己的临时根。

`test_profile_delete.py`和`test_delete_integration.py`也已纳入默认入口，验证临时合成资料的彻底删除、混合备份过滤、共享数据保护、占用/中断恢复、pending禁用及同步任务兼容。不得用真实窗口试删；实际安装仅通过只读检查器比对前后摘要。

`test_background_probe.py`验证后台启动仅用于独立离线空白验证，保留签名、文件和网络门禁，正常浏览器启动不加后台参数。它不会启动真实进程；真实空白后台验证的显式专项和边界见`docs/后台环境验证.md`。

`test_ip_info_page.py`验证信息页创建与恢复复用、保护其他标签、实际relay门禁及失败保留窗口；`test_proxy_runtime_stability.py`验证共享隧道空闲时间、持续上传/下载、取消清理及断线后重连。均只使用合成资料或回环服务，已加入默认自检；在线测试使用独立工具及用户指定测试代理池，见`docs/代理与IP信息页.md`。

`test_installation_inspector.py` 已纳入默认安全自检，只使用临时合成目录、加密记录和 SQLite 数据库。它验证检查器的基线结构、设置解密/路径校验、严格占用复核、WAL 数据认证、复制预算/超时、原件无数据库连接/侧文件，以及报告原子写入。它不读取真实安装资料、不启动探针或浏览器。

安装检查器只在临时副本连接目录库和浏览器的三个固定数据库，复制现有 WAL，扫描前后核对原件指纹；运行、状态不可核实或资料发生变化时不算完整成功。新报告增加全表目录摘要，旧报告仍按原密文与 profile 摘要比较，并明确标记旧报告不具备全表摘要，不能据此补证此前外层索引或来源绑定未变。

`test_local_runtime_recovery.py` 使用临时加密目录，覆盖续签/保存提交结果不确定时的签名文件保留，以及下载目录启用、撤销过程的文件和目录提交失败恢复；已加入默认入口。`test_project_contracts.py` 还验证全局设置与所有窗口的待应用标记在同一事务保存。前端回归覆盖迟到的列表和初始化回复，生命周期回归覆盖可见窗口就绪和完整指纹参数的进程身份核对。
