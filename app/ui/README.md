# 本地窗口管理界面

原生HTML/CSS/JavaScript，由pywebview和随包WebView2加载`index.html`；无框架、构建步骤、CDN或运行时下载。入口与退出回调位于`../local_browser.pyw`，后端功能总览见[架构与功能](../../docs/架构与功能.md)。

## 文件与状态

- `index.html`：静态页面、抽屉、同步和确认对话框。
- `style.css`：桌面和窄屏布局，加载、禁用及只读状态。
- `app.js`：桥接、列表与选择、表单草稿、同步任务、设置与分组。

主列表搜索支持名称、序号、备注、分组、标签及代理IP/端口。换行、逗号或分号分隔的最多10个不同搜索项按“匹配任意一项”筛选，大小写及重复项忽略；批量输入完整IPv4时按完整地址匹配，避免尾号1同时匹配到11，单项搜索及包含空格的短语保持原有行为。超过10项明确提示并暂停显示结果，不静默截断；分组、标签和运行状态筛选继续叠加。搜索框可直接粘贴多行，重置筛选会清空批量输入。列表表头固定于滚动区域顶部，横向滚动仍与各列对齐。

`state.settings`仅存后端确认的设置；`settingsDraft`用于编辑，放弃修改不影响关闭确认和退出规则。保存提交快照，提交期间的后续编辑保持未保存，不被旧响应覆盖。

窗口编辑使用独立draft、drawerSession及代理revision/request标记。Cookie文件读取绑定会话与读取序号，新选择或手工编辑使旧读取失效；代理解析/检测也拒绝迟到响应串入另一窗口。分组提交期间冻结新增、移除与重命名，延迟确认核对草稿身份；提交成功立即接受服务确认的分组身份，列表刷新失败单独提示，避免下次改名丢失归属。列表状态轮询只更新运行状态和最近打开时间，不替换编辑草稿。

指纹控件只读，保存不采集、校验或重新转换disabled字段；未知键按原记录保留。Cookie文件上限5MB，后端有效文本另有2MB限制。归档只移入可恢复回收站。

主列表“删除”紧邻“移至回收站”，行菜单及回收站提供相同入口；回收站独立维护选择。确认默认焦点为取消，提交前重新核对窗口/面板/选择身份。删除分段串行，只有逐项回执同时明确`deleted:true`和`cleanup_complete:true`才计成功；已退役但存储清理未完单独报错。pending窗口禁止打开、编辑和恢复，仍可重试删除。

已删ID只保存在当前页面内存，用于拒绝迟到的列表/详情响应；不写入持久墓碑。删除后清理草稿、选择和来源预览，原比特来源仍可重新导入。

删除后用`sync_status {job_id,missing_ok:true}`核对当前任务：明确返回null才清空失效任务，存在则刷新结果和计数，读取失败保留任务并可重试。请求代次防止旧任务响应恢复已清状态，也防止空bootstrap清除新运行任务。

## 同步流程

主按钮重新预览并自动同步全部ready项；“预览来源”只预览，支持搜索、每页50项和手工选择。任务运行中再次点击只打开同一任务进度。两个入口都明确提交`source_keys`，没有可导入项就不创建空任务。

以`capabilities.independent_runtime`决定来源说明。当前可扫描比特新建且已经打开过、正常关闭并完整落盘的本机窗口；首次缺配置会自动使用正常登录会话联网补齐，日常独立运行不回原厂。未知或变化的来源必须完整核对后才成功，不用缺省指纹猜测补齐。

重复导入跳过已有来源；来源改动或删除不覆盖、删除本地副本。来源运行中、不完整或不支持的项目不可选。取消只停止后续项，界面继续查询最终结果。

单批最多9999，来源总列表不截断；默认/全选/单选及最终提交均校验上限，明确未选余量可下批处理。同一任务轮询不重叠，上次请求结束约1秒后再读；关闭面板仍在后台读取。连续3次失败后暂停并提供恢复入口，避免误报任务完成。后端返回尾100项及全量计数，不传全部历史结果。

bootstrap的`sync_job`恢复持久任务；`interrupted`停止轮询并显示“继续剩余同步”，调用`resume_sync {job_id}`后继续原任务。请求代次在start/resume/cancel进入和结束时推进，迟到状态/错误/bootstrap不能回退已确认任务。旧轮询仍占唯一门闩，结束后补拉新代状态。常规状态合并使用ID Map，避免万条记录逐条线性查找。

## 桥接契约

统一调用`window.pywebview.api.request(action,payload)`，响应`{ok,data,error?}`。没有模拟成功；服务未连接时明确提示。配置及API结果不写入控制台。

| 动作 | 用途与边界 |
|---|---|
| `bootstrap/list/detail/status` | 初始化、列表、详情及状态；能力标志控制说明 |
| `save {profile}` | 仅编辑已有记录；后端拒绝新建及修改指纹 |
| `open/close/activate/archive/restore/delete {id}` | 单窗口操作、可恢复归档及不可恢复删除 |
| `batch {action,ids}` | open/close/archive/delete；界面每100个ID顺序提交，删除额外返回逐项results及完整清理回执 |
| `sync_preview/sync_windows/sync_status/resume_sync/cancel_sync` | 预览、启动、恢复和管理持久增量任务 |
| `proxy_parse/proxy_test` | 统一后端解析；仅`success:true`视为检测成功 |
| `groups_save {groups,renames}` | 保存分组及改名映射 |
| `settings_get/settings_save` | 保存内核路径、下载目录、默认页和退出/关闭策略 |
| `choose_file/choose_folder` | 原生路径选择，取消返回空值 |
| `export_profiles` | 加密配置导出，不含完整浏览器资料 |
| `window_control` | 受限的管理器窗口操作 |

新增`creation_options/create_windows/creation_status/cancel_creation/resume_creation/creation_randomize`动作。创建复用详情抽屉，仅新建草稿允许编辑指纹；提交使用同一请求ID重试，批次进度持久恢复，迟到bootstrap/轮询不能回退新状态。旧`create/copy/randomize/import_profiles`动作仍拒绝，来源同步和已有窗口只读指纹保留。

代理粘贴只判断是否完整地址，具体语法交给后端，避免维护第二套解析规则。变更参数会使旧检测失效；同表单不并发检测，只为最新代理保留一次待检测。保存等待当前解析完成，失败不无限重试。代理修改须先关闭窗口，保存后重开。

状态轮询在上次请求结束约3秒后再读，隐藏时暂停，恢复可见后立即读。批量分段只解决后端100项上限，不改变单次请求内的执行顺序和并发。

## 验证

```powershell
node --test tests/frontend-state.test.js
.\runtime\python\python.exe tools\check_project.py
```

从项目根目录执行。前者用Node内置VM、内存DOM和实际前端函数覆盖异步草稿与批量边界；后者统一运行语法、项目契约和隔离夹具。产品运行不需要Node。

内存DOM通过不等于真实WebView渲染、焦点环或原生文件对话框通过。旧Playwright脚本与布局截图保存在`analysis/`；部分仍假设允许新建/随机/复制，不能批量作为当前端到端验收。当前专项和历史证据见[analysis索引](../../analysis/README.md)。
