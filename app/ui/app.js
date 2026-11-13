"use strict";

// All configuration stays in the local WebView and is sent only to the local bridge.
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) =>
  Array.from(root.querySelectorAll(selector));
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
const copy = (value) => JSON.parse(JSON.stringify(value ?? {}));
const icons = {
  windows:
    '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  folder:
    '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1Z"/>',
  globe:
    '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z"/>',
  settings:
    '<path d="m10 3-.7 2.4-2 .9L5 5.7 2.9 9.3l1.8 1.8v1.8l-1.8 1.8L5 18.3l2.3-.6 2 .9.7 2.4h4l.7-2.4 2-.9 2.3.6 2.1-3.6-1.8-1.8v-1.8l1.8-1.8L19 5.7l-2.3.6-2-.9L14 3Z"/><circle cx="12" cy="12" r="3"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-1 .5-1 1.2-1 2M12 17h.01"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  refresh:
    '<path d="M20 7v5h-5M4 17v-5h5M5 8a7.5 7.5 0 0 1 12-3l3 3M4 16l3 3a7.5 7.5 0 0 0 12-3"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  import: '<path d="M12 3v12m-4-4 4 4 4-4M4 15v5h16v-5"/>',
  export: '<path d="M12 16V4m-4 4 4-4 4 4M4 15v5h16v-5"/>',
  play: '<path d="m8 5 10 7-10 7Z"/>',
  stop: '<rect x="5" y="5" width="14" height="14" rx="2"/>',
  edit: '<path d="m15 4 5 5-11 11-6 1 1-6Zm-2 2 5 5"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  profile:
    '<rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="9" cy="9" r="2"/><path d="M6 16v-1a3 3 0 0 1 6 0v1M15 8h3M15 12h3M15 16h3"/>',
  fingerprint:
    '<path d="M4 10a8 8 0 0 1 16 0M7 19c1-3 0-5 0-8a5 5 0 0 1 10 0c0 3 0 6-1 9M10 21c2-5 0-8 1-11a1.5 1.5 0 0 1 3 1c0 3 1 7-1 11M3 14l1-2M20 13l1 3"/>',
  cookie:
    '<path d="M20 13a6 6 0 0 1-9-9A9 9 0 1 0 20 13Z"/><path d="M8 10h.01M7 16h.01M13 17h.01M12 12h.01M18 5h.01M21 9h.01"/>',
  restore: '<path d="M4 4v6h6M4 10a8 8 0 1 1 0 5M12 8v5l3 2"/>',
  apple:
    '<path d="M15 3c0 2-1 3-3 3 0-2 1-3 3-3ZM12 8c-5-4-10 1-7 7 1 3 3 6 5 5 1-1 3-1 4 0 2 1 4-2 5-5-4-2-3-5-1-6-2-2-4-2-6-1Z"/>',
  linux:
    '<path d="M8 10c-1-4 0-7 4-7s5 3 4 7l4 8-4 3-4-2-4 2-4-3Z"/><path d="m10 10 2 2 2-2M10 7h.01M14 7h.01"/>',
  check: '<path d="m5 12 4 4 10-10"/>',
};
const svg = (name) =>
  `<svg viewBox="0 0 24 24" aria-hidden="true">${icons[name] || icons.windows}</svg>`;
function hydrateIcons(root = document) {
  $$("[data-icon]", root).forEach((el) => {
    el.innerHTML = svg(el.dataset.icon);
  });
}

const defaultFingerprint = {
  ostype: "PC",
  os: "Win32",
  coreProduct: "chrome",
  coreVersion: "",
  version: "",
  userAgent: "",
  platformVersion: "",
  architecture: "x86",
  osVersion: "",
  timeZoneOffset: 0,
  ignoreHttpsErrors: false,
  precisionData: "",
  hostIP: "",
  bitness: 64,
  iswow64: false,
  uamodel: "",
  navigatorVendor: "Google Inc.",
  webglparameterscode: "",
  modelName: "",
  manufacturerName: "",
  totalDiskSpace: "",
  hardwareConcurrency: 8,
  deviceMemory: 8,
  languages: "zh-CN,zh",
  displayLanguages: "zh-CN",
  timeZone: "Asia/Shanghai",
  isIpCreateLanguage: true,
  isIpCreateTimeZone: true,
  isIpCreateDisplayLanguage: true,
  resolutionType: "0",
  resolution: "1920x1080",
  openWidth: 1280,
  openHeight: 800,
  fontType: "0",
  font: "",
  canvas: "0",
  canvasValue: null,
  webGL: "0",
  webGLValue: null,
  webGLMeta: "0",
  webGLManufacturer: "",
  webGLRender: "",
  audioContext: "0",
  audioContextValue: null,
  mediaDevice: "1",
  speechVoices: "0",
  mediaDeviceValue: null,
  speechVoicesValue: null,
  clientRectNoiseEnabled: true,
  clientRectNoiseValue: 0,
  doNotTrack: "0",
  webRTC: "3",
  position: "0",
  isIpCreatePosition: true,
  lat: "",
  lng: "",
  defaultAccuracy: 100,
  colorDepth: 24,
  devicePixelRatio: 1,
  disableSslCipherSuitesFlag: false,
  disableSslCipherSuites: "",
  portScanProtect: "1",
  portWhiteList: "",
  deviceInfoEnabled: false,
  computerName: "",
  macAddr: "",
  webgpu: null,
  plugins: "",
  enablePlugins: false,
  windowSizeLimit: false,
  launchArgs: "",
};
const preferenceDefinitions = [
  ["mute_audio", "静音", "启动时将窗口设为静音。"],
  [
    "disable_gpu",
    "禁用 GPU 加速",
    "以软件方式渲染；可能影响页面性能与图形能力。",
  ],
  ["disable_notifications", "禁用网页通知", "阻止网站发送桌面通知。"],
  [
    "abort_images",
    "禁止加载图片",
    "减少图片请求，部分网站内容可能无法完整显示。",
  ],
  [
    "abort_media",
    "禁止加载音视频",
    "使用本地媒体资源拦截；不保证拦截所有脚本、blob 或 MSE 播放。",
  ],
  ["disable_clipboard", "禁用网页剪贴板", "限制网页读写剪贴板。"],
  ["allowed_signin", "允许浏览器账户登录", "控制浏览器内核的账户登录功能。"],
  ["credentials_service", "允许保存密码", "启用内核的密码保存服务。"],
  ["disable_translate", "关闭自动翻译", "不主动显示网页翻译提示。"],
  [
    "memory_saver",
    "节省内存模式",
    "保存内核节省内存选项，实际效果取决于内核支持。",
  ],
  ["restore_session", "恢复上次会话", "下次启动时尝试恢复之前的标签页。"],
];
const defaultProfile = {
  name: "",
  group: "",
  tags: [],
  remark: "",
  os: "Windows",
  core_version: "",
  proxy: { type: "noproxy", host: "", port: "", username: "", password: "" },
  platform: "",
  username: "",
  password: "",
  fa_secret: "",
  allow_multi_open: false,
  duplicate_check: true,
  urls: [],
  cookie_text: "",
  fingerprint: defaultFingerprint,
  preferences: Object.fromEntries(
    preferenceDefinitions.map(([key]) => [key, false]),
  ),
};
const state = {
  profiles: [],
  groups: [],
  tags: [],
  cores: [],
  defaults: copy(defaultProfile),
  capabilities: {},
  settings: {},
  settingsDraft: {},
  selected: new Set(),
  recycleSelected: new Set(),
  deletedIds: new Set(),
  deleteBusy: false,
  panel: "profiles",
  filter: "all",
  search: "",
  group: "",
  tag: "",
  sort: "seq",
  direction: 1,
  page: 1,
  pageSize: 20,
  draft: null,
  drawerSession: 0,
  cookieReadRequest: 0,
  dirty: false,
  section: "basic",
  saving: false,
  connected: false,
  loading: false,
  groupDraft: [],
  groupOriginal: [],
  groupSources: [],
  groupsSaving: false,
  settingsDirty: false,
  settingsSaving: false,
  settingsLoaded: false,
  settingsRevision: 0,
  settingsDraftRevision: 0,
  settingsReadRequest: 0,
  windowLayout: { loading: false, loaded: false, saving: false, arranging: false, session: 0, settings: null, returnFocus: null },
  creatingDraft: false,
  creation: { job: null, requestId: null, revision: 0, fingerprintRevision: 0, timer: null, reading: false, opening: false },
  operationIds: new Set(),
  operationActions: new Map(),
  batchBusy: false,
  statusRefreshing: false,
  statusTimer: null,
  statusRevision: 0,
  profileRenderPending: false,
  profileFocusTimer: null,
  proxyRevision: 0,
  proxyParseRequest: 0,
  proxyParsePromise: null,
  proxyTestActive: false,
  proxyTestQueued: null,
  preparingSave: false,
  sync: {
    preview: [], names: new Map(), selected: new Set(), search: "", page: 1,
    previewRevision: 0, previewId: null,
    loading: false, starting: false, jobId: null, status: null,
    timer: null, polling: false, pollErrors: 0, pollPaused: false, requestRevision: 0,
    cancelling: false, cancelRequested: false, finishedJobId: null,
    error: "", returnFocus: null, deferred: 0,
  },
};

function getPath(object, path) {
  return path.split(".").reduce((value, key) => value?.[key], object);
}
function setPath(object, path, value) {
  const keys = path.split(".");
  let node = object;
  keys.slice(0, -1).forEach((key) => {
    if (!node[key] || typeof node[key] !== "object") node[key] = {};
    node = node[key];
  });
  node[keys.at(-1)] = value;
}
function mergedProfile(profile = {}) {
  const result = {
    ...copy(defaultProfile),
    ...copy(state.defaults),
    ...copy(profile),
  };
  result.fingerprint = {
    ...defaultFingerprint,
    ...state.defaults?.fingerprint,
    ...profile.fingerprint,
  };
  result.proxy = {
    ...defaultProfile.proxy,
    ...state.defaults?.proxy,
    ...profile.proxy,
  };
  result.preferences = {
    ...defaultProfile.preferences,
    ...state.defaults?.preferences,
    ...profile.preferences,
  };
  result.tags = Array.isArray(result.tags)
    ? result.tags
    : splitList(result.tags);
  result.urls = Array.isArray(result.urls)
    ? result.urls
    : String(result.urls || "")
        .split(/\r?\n/)
        .filter(Boolean);
  return result;
}
function splitList(value) {
  return [
    ...new Set(
      String(value || "")
        .split(/[,，\n]/)
        .map((part) => part.trim())
        .filter(Boolean),
    ),
  ];
}
function isArchived(profile) {
  return Boolean(
    profile.archived || profile.archived_at || profile.status === "archived",
  );
}
function isRunning(profile) {
  return (
    ["running", "opened", "open", "opening", "closing", "launching"].includes(
      String(profile.status).toLowerCase(),
    ) || profile.is_running === true
  );
}
function isDeletePending(profile) {
  return profile?.delete_pending === true || profile?.config_status === "delete_pending";
}
function displayDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")} ${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
}
function profileById(id) {
  return state.profiles.find((profile) => String(profile.id) === String(id));
}
function apiAvailable() {
  return Boolean(window.pywebview?.api?.request);
}
async function api(action, payload = {}) {
  if (!apiAvailable())
    throw new Error("尚未连接到本地服务，请在桌面程序中打开此界面。");
  let result = await window.pywebview.api.request(action, payload);
  if (typeof result === "string") {
    try {
      result = JSON.parse(result);
    } catch {
      throw new Error("本地服务返回了无效响应。");
    }
  }
  if (!result || result.ok !== true)
    throw new Error(String(result?.error || "本地服务未完成此操作。"));
  return result.data;
}
function toast(message, type = "info") {
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  const body = document.createElement("span");
  body.textContent = String(message);
  const close = document.createElement("button");
  close.className = "toast-close";
  close.textContent = "×";
  close.setAttribute("aria-label", "关闭提示");
  close.onclick = () => item.remove();
  item.append(body, close);
  $("#toast-region").append(item);
  setTimeout(() => item.remove(), type === "error" ? 10000 : 5000);
}
function showServiceError(message) {
  const el = $("#service-error");
  el.textContent = message || "";
  el.hidden = !message;
}
function showDrawerError(message) {
  const el = $("#drawer-error");
  el.textContent = message || "";
  el.hidden = !message;
  if (message) $("#drawer-scroll").scrollTo({ top: 0, behavior: "smooth" });
}
function setConnection(connected, message) {
  state.connected = connected;
  const el = $("#connection-status");
  el.textContent = message || (connected ? "本地服务已连接" : "本地服务未连接");
  el.className = `connection-status ${connected ? "connected" : "failed"}`;
}
function confirmAction(title, message, accept = "确定") {
  return new Promise((resolve) => {
    const dialog = $("#confirm-dialog");
    if (dialog.open) {
      resolve(false);
      return;
    }
    $("#confirm-title").textContent = title;
    $("#confirm-message").textContent = message;
    $("#confirm-accept").textContent = accept;
    dialog.returnValue = "cancel";
    dialog.addEventListener(
      "close",
      () => resolve(dialog.returnValue === "confirm"),
      { once: true },
    );
    dialog.showModal();
    $("#confirm-cancel").focus();
  });
}

const defaultWindowLayout = {
  mode: "auto", monitor: "primary", start_x: 0, start_y: 0,
  width: 640, height: 600, columns: 3, gap_x: 0, gap_y: 0,
  step_x: 30, step_y: 30, order: "asc",
};
const windowLayoutNumbers = {
  start_x: ["起点 X", 0], start_y: ["起点 Y", 0],
  width: ["窗口宽度", 120], height: ["窗口高度", 40],
  columns: ["每行窗口数", 1], gap_x: ["水平间距", 0], gap_y: ["垂直间距", 0],
  step_x: ["水平偏移", 0], step_y: ["垂直偏移", 0],
};
function showWindowLayoutError(message = "") {
  $("#window-layout-error").textContent = message;
  $("#window-layout-error").hidden = !message;
}
function renderWindowLayout() {
  const layout = state.windowLayout;
  const busy = layout.saving || layout.arranging;
  $("#arrange-windows").disabled = layout.loading || busy;
  $("#arrange-windows").classList.toggle("is-loading", layout.arranging);
  $("#window-layout-settings").disabled = layout.loading || busy;
  $("#window-layout-loading").hidden = !layout.loading;
  $("#window-layout-form").hidden = !layout.loaded;
  $("#window-layout-form").inert = layout.loading || busy;
  $("#window-layout-close").disabled = busy;
  $("#window-layout-cancel").disabled = busy;
  $("#window-layout-save").disabled = !layout.loaded || busy;
  $("#window-layout-save-arrange").disabled = !layout.loaded || busy;
  $("#window-layout-save").textContent = layout.saving && !layout.arranging ? "正在保存…" : "保存";
  $("#window-layout-save-arrange").textContent = layout.arranging ? "正在排列…" : "保存并排列";
  const mode = $("#window-layout-mode").value;
  $("#window-layout-auto-note").hidden = mode !== "auto";
  $("#window-layout-manual").hidden = mode === "auto";
  $("#window-layout-grid").hidden = mode !== "grid";
  $("#window-layout-cascade").hidden = mode !== "cascade";
}
function closeWindowLayout() {
  const layout = state.windowLayout;
  if (layout.saving || layout.arranging) return;
  layout.session++;
  layout.loading = false;
  layout.loaded = false;
  $("#window-layout-dialog").close();
  renderWindowLayout();
  layout.returnFocus?.focus();
}
async function openWindowLayout() {
  const layout = state.windowLayout;
  const dialog = $("#window-layout-dialog");
  if (layout.saving || layout.arranging || dialog.open) return;
  const session = ++layout.session;
  const current = () => session === layout.session && dialog.open;
  layout.returnFocus = document.activeElement;
  layout.loading = true;
  layout.loaded = false;
  showWindowLayoutError();
  renderWindowLayout();
  dialog.showModal();
  try {
    const data = await api("window_layout_get");
    if (!current()) return;
    if (!data?.settings || !Array.isArray(data.monitors)) throw new Error("未能读取排列设置，请关闭后重试。");
    const settings = { ...defaultWindowLayout, ...data.settings };
    const monitors = data.monitors.filter((monitor) => monitor && typeof monitor.id === "string");
    const missingMonitor = settings.monitor !== "primary" && !monitors.some((monitor) => monitor.id === settings.monitor);
    $("#window-layout-monitor").innerHTML = '<option value="primary">主显示器（自动跟随）</option>' + monitors.map((monitor) =>
      `<option value="${esc(monitor.id)}">${esc(monitor.label || `显示器${monitor.primary ? " · 主屏" : ""} · ${monitor.width} × ${monitor.height}`)}</option>`).join("");
    if (missingMonitor) settings.monitor = "primary";
    layout.settings = settings;
    for (const key of Object.keys(defaultWindowLayout)) $("#window-layout-" + key).value = String(settings[key]);
    $("#window-layout-monitor-note").textContent = missingMonitor || data.monitor_fallback ? "原显示器当前不可用，本次使用主显示器。" : "";
    $("#window-layout-monitor-note").hidden = !(missingMonitor || data.monitor_fallback);
    layout.loaded = true;
  } catch (error) {
    if (current()) showWindowLayoutError(error.message);
  } finally {
    if (current()) {
      layout.loading = false;
      renderWindowLayout();
    }
  }
}
function readWindowLayout() {
  const settings = {};
  for (const key of Object.keys(defaultWindowLayout)) settings[key] = $("#window-layout-" + key).value;
  const active = new Set(settings.mode === "auto" ? [] : ["start_x", "start_y", "width", "height",
    ...(settings.mode === "grid" ? ["columns", "gap_x", "gap_y"] : ["step_x", "step_y"])]);
  for (const [key, [label, minimum]] of Object.entries(windowLayoutNumbers)) {
    const value = Number(settings[key]);
    if (!String(settings[key]).trim() || !Number.isSafeInteger(value) || value < minimum) {
      if (!active.has(key)) {
        settings[key] = state.windowLayout.settings?.[key] ?? defaultWindowLayout[key];
        continue;
      }
      $("#window-layout-" + key).focus();
      throw new Error(`“${label}”须填写不小于 ${minimum} 的整数。`);
    }
    settings[key] = value;
  }
  return settings;
}
function reportWindowArrangement(result) {
  if (!result || !Number.isInteger(result.arranged)) throw new Error("未能确认排列结果，请检查窗口后重试。");
  const arranged = syncCount(result.arranged), failed = syncCount(result.failed), skipped = syncCount(result.skipped);
  let message = result.message;
  if (!message) {
    message = syncCount(result.total) ? `已排列 ${arranged} 个窗口` : "本包暂无可排列的已打开窗口";
    if (failed) message += `，失败 ${failed} 个`;
    if (skipped) message += `，跳过 ${skipped} 个`;
  }
  toast(message, failed ? "error" : arranged ? "success" : "info");
}
async function arrangeWindows() {
  const layout = state.windowLayout;
  if (layout.loading || layout.saving || layout.arranging) return;
  layout.arranging = true;
  renderWindowLayout();
  try {
    reportWindowArrangement(await api("arrange_windows"));
  } catch (error) {
    toast(error.message, "error");
  } finally {
    layout.arranging = false;
    renderWindowLayout();
  }
}
async function saveWindowLayout(andArrange = false) {
  const layout = state.windowLayout;
  const dialog = $("#window-layout-dialog");
  if (!dialog.open || !layout.loaded || layout.loading || layout.saving || layout.arranging) return;
  let settings;
  showWindowLayoutError();
  try { settings = readWindowLayout(); }
  catch (error) { showWindowLayoutError(error.message); return; }
  const session = layout.session;
  let saved = false, completed = false;
  layout.saving = true;
  renderWindowLayout();
  try {
    const data = await api("window_layout_save", { settings });
    if (!data?.settings) throw new Error("未能确认设置保存结果，请重新读取后确认。");
    saved = true;
    if (andArrange) {
      layout.arranging = true;
      renderWindowLayout();
      reportWindowArrangement(await api("arrange_windows"));
    } else toast("排列设置已保存", "success");
    completed = true;
  } catch (error) {
    const message = saved ? `排列设置已保存，排列未完成：${error.message}` : error.message;
    if (session === layout.session && dialog.open) showWindowLayoutError(message);
    else toast(message, "error");
  } finally {
    layout.saving = false;
    layout.arranging = false;
    renderWindowLayout();
    if (completed && session === layout.session) closeWindowLayout();
  }
}

function sourceGuidance() {
  if (state.capabilities.independent_runtime) return {
    helpTitle: "导入本机完整窗口",
    helpDescription: "点击“同步窗口”先检测本机来源，查看可同步数量后，再点击“开始同步”复制。新建窗口在比特中打开过、资料完整落地并正常关闭后，也会参与来源检查；没有比特不影响本地已有窗口和新建窗口。",
    helpNotice: "本地副本保留来源指纹，界面仅供查看。只有完整配置、内核和浏览器资料通过检查，来源已正常关闭且复制保存完成才计为成功；缺失配置或资料时会逐项说明原因。",
    listEmpty: "点击“同步窗口”，检查并导入比特本机完整窗口资料",
    syncNote: "先自动检测本机来源并显示数量，点击“开始同步”后才复制资料",
    syncExplanation: "已准备来源和在比特中打开过的新窗口均会参与检查。检测本机来源并读取名称、备注，不复制窗口资料；读取名称、备注可能需要比特的有效登录会话及联网，检测结果保留10分钟。开始同步后仍须完成配置、内核和完整资料检查，新来源缺少配置时可能需要比特的有效登录会话及联网。已导入副本不会重复、覆盖，来源删除不会删除本地副本。",
    previewLoading: "正在检查本机来源配置及完整资料…",
    previewEmpty: "未发现可导入的本机来源。没有比特不影响本地已有窗口和新建窗口；比特新窗口请先在比特中打开，待完整资料落地后正常关闭，再重新检测。",
    sourceOpen: "请正常关闭来源窗口后重新预览；完整配置和浏览器资料仍须通过检查。",
    missingData: "此来源缺少完整的本地配置或浏览器资料，暂不能导入。",
  };
  return {
    helpTitle: "从比特同步窗口",
    helpDescription: "先在比特配置好窗口并正常关闭，再点击“同步窗口”。仅复制本机已有完整资料的窗口；读取完整配置和签名仍需联网及有效授权，不处理其他云端窗口。",
    helpNotice: "指纹请先在比特配置后导入，本地界面仅供查看。来源窗口运行中或资料尚未完整落地时不能完成同步，请正常关闭来源窗口后重新预览；只有资料复制与保存完成才会计为成功。",
    listEmpty: "点击“同步窗口”，从比特复制本机已有完整资料的窗口",
    syncNote: "直接扫描本机资料，无需启动比特客户端；读取完整配置和签名仍需联网及有效授权",
    syncExplanation: "同步会将窗口信息、指纹和浏览器资料复制为独立本地副本。仅增量添加新窗口，已导入的副本不会重复、覆盖；来源删除不会删除本地副本。来源运行中请先正常关闭，资料未完整落地时不会记为成功。",
    previewLoading: "正在读取比特本机窗口资料…",
    previewEmpty: "未发现可同步的本机窗口。请先在比特准备好窗口并正常关闭，使资料完整落地。",
    sourceOpen: "请正常关闭来源窗口后重新预览。",
    missingData: "请在比特中确认资料完整落地后再试。",
  };
}
function renderSourceGuidance() {
  const text = sourceGuidance();
  $("#help-source-title").textContent = text.helpTitle;
  $("#help-source-description").textContent = text.helpDescription;
  $("#help-import-notice").textContent = text.helpNotice;
}

const SYNC_BATCH_LIMIT = 9999;
const syncStatusLabels = {
  ready: "可导入", already_imported: "已导入 · 跳过",
  source_open: "来源运行中", missing_data: "资料不完整", unsupported: "暂不支持",
  pending: "等待同步", queued: "等待同步", running: "正在同步", copying: "正在复制",
  completed: "导入成功", imported: "导入成功", success: "导入成功",
  skipped: "已跳过", failed: "导入失败", cancelled: "已取消",
};
const syncProgressPhases = {
  checking: "检查资料", preparing: "准备窗口配置", engine: "准备独立内核",
  inventory: "统计资料文件", source_hash: "读取来源校验摘要", copying: "复制浏览器资料",
  source_verify: "核对来源未变化", copy_verify: "校验复制完整性", validating: "验证窗口配置",
  portable_keys: "准备便携密钥", cookies: "准备登录资料",
  baseline_first: "首次环境基线采集", baseline_second: "第二次环境基线采集",
  baseline_verify: "验证环境基线", flushing: "保存资料到磁盘", final_hash: "最终完整性校验",
  committing: "提交本地窗口",
};
function syncRunning() {
  const sync = state.sync;
  return sync.starting || Boolean(sync.jobId && sync.status?.state === "running");
}
function syncInterrupted() {
  return Boolean(state.sync.jobId && state.sync.status?.state === "interrupted");
}
function boundedSyncStatus(status) {
  const items = Array.isArray(status.items) ? status.items : [];
  return { ...status, progress: status.state === "running" ? status.progress || null : null,
    items: items.slice(-100), items_total: Math.max(syncCount(status.items_total), items.length) };
}
function invalidateSyncStatus() {
  // A persisted job keeps its ID across resume, so ID checks alone cannot reject old replies.
  state.sync.requestRevision++;
  clearTimeout(state.sync.timer);
}
function clearSyncJob() {
  const sync = state.sync;
  invalidateSyncStatus();
  sync.jobId = null;
  sync.status = null;
  sync.cancelRequested = false;
  sync.finishedJobId = null;
  sync.pollErrors = 0;
  sync.pollPaused = false;
  sync.previewId = null;
  sync.deferred = 0;
  $("#sync-result-list").innerHTML = "";
  showSyncError();
  renderSync();
}
async function refreshSyncAfterDelete() {
  const sync = state.sync;
  if (!sync.jobId) return true;
  if (sync.starting || sync.cancelling) return false;
  invalidateSyncStatus();
  const jobId = sync.jobId;
  const revision = sync.requestRevision;
  const current = () => jobId === sync.jobId && revision === sync.requestRevision && !sync.starting && !sync.cancelling;
  try {
    const status = await api("sync_status", { job_id: jobId, missing_ok: true });
    if (!current()) return !sync.jobId && !sync.starting && !sync.cancelling;
    if (status === null) clearSyncJob();
    else {
      if (!status?.job_id || String(status.job_id) !== jobId || !["running", "completed", "failed", "cancelled", "interrupted"].includes(status.state)) throw new Error();
      invalidateSyncStatus();
      sync.status = boundedSyncStatus(status);
      sync.cancelRequested = Boolean(status.cancel_requested);
      sync.pollErrors = 0;
      sync.pollPaused = false;
      showSyncError();
      renderSync();
      scheduleSyncStatus(0);
    }
    return true;
  } catch {
    if (current()) {
      sync.pollPaused = true;
      showSyncError("删除结果已返回，但同步任务核对失败。请刷新管理器或读取进度确认结果，不要重复开始同步。");
      renderSync();
    }
    return false;
  }
}
function restoreSyncJob(status) {
  const sync = state.sync;
  if (!status?.job_id || !["running", "interrupted"].includes(status.state) || sync.starting || sync.cancelling) return;
  const jobId = String(status.job_id);
  if (sync.jobId === jobId && ["completed", "failed", "cancelled"].includes(sync.status?.state)) return;
  invalidateSyncStatus();
  sync.jobId = jobId;
  sync.status = boundedSyncStatus(status);
  sync.cancelRequested = Boolean(status.cancel_requested);
  sync.pollErrors = 0;
  sync.pollPaused = false;
  sync.previewId = null;
  sync.deferred = 0;
  showSyncError();
  renderSync();
  scheduleSyncStatus(0);
}
function syncCanImport(item) {
  return item.status === "ready" && item.has_local_data !== false;
}
function syncCount(value) {
  return Number.isFinite(Number(value)) ? Math.max(0, Math.floor(Number(value))) : 0;
}
function showSyncError(message = "") {
  state.sync.error = message;
  $("#sync-error").textContent = message;
  $("#sync-error").hidden = !message;
}
function openSyncDialog() {
  const dialog = $("#sync-dialog");
  if (!dialog.open) {
    state.sync.returnFocus = document.activeElement;
    dialog.showModal();
  }
  if (syncRunning() || syncInterrupted()) {
    renderSync();
    if (state.sync.pollPaused) resumeSyncStatus();
    return;
  }
  if (!state.sync.loading) loadSyncPreview();
}
function closeSyncDialog() {
  $("#sync-dialog").close();
  state.sync.returnFocus?.focus();
}
async function loadSyncPreview() {
  const sync = state.sync;
  if (sync.loading || syncRunning() || syncInterrupted()) return;
  const previewRevision = ++sync.previewRevision;
  sync.previewId = null;
  invalidateSyncStatus();
  sync.loading = true;
  sync.jobId = null;
  sync.status = null;
  sync.deferred = 0;
  sync.preview = [];
  sync.names.clear();
  sync.selected.clear();
  sync.page = 1;
  sync.search = "";
  $("#sync-search").value = "";
  $("#sync-search").rows = 1;
  showSyncError();
  renderSync();
  try {
    const data = await api("sync_preview");
    if (previewRevision !== sync.previewRevision) return;
    if (!Array.isArray(data?.items)) throw new Error("本地服务未返回同步预览，请重试。");
    if (typeof data.preview_id !== "string" || !data.preview_id) throw new Error("本地服务未返回有效检测结果，请重新检测。");
    sync.previewId = data.preview_id;
    const seen = new Set();
    sync.preview = data.items.filter((item) => {
      if (!item || typeof item.source_key !== "string" || !item.source_key || seen.has(item.source_key)) return false;
      seen.add(item.source_key);
      return true;
    });
    sync.selected = new Set(sync.preview.filter(syncCanImport).slice(0, SYNC_BATCH_LIMIT).map((item) => item.source_key));
    sync.names = new Map(sync.preview.map((item) => [item.source_key, item.name || "未命名窗口"]));
  } catch (error) {
    if (previewRevision !== sync.previewRevision) return;
    showSyncError(error.message);
  } finally {
    if (previewRevision === sync.previewRevision) {
      sync.loading = false;
      renderSync();
    }
  }
}
function renderSync() {
  const sync = state.sync;
  const independent = Boolean(state.capabilities.independent_runtime);
  const guidance = sourceGuidance();
  $("#sync-title").textContent = independent ? "导入本地窗口资料" : "从比特同步窗口";
  $("#sync-source-note").textContent = guidance.syncNote;
  $("#sync-explanation").textContent = guidance.syncExplanation;
  const running = syncRunning();
  const interrupted = syncInterrupted();
  const hasJob = Boolean(sync.jobId);
  $("#create-button").innerHTML = `${svg("refresh")}${running || interrupted ? "同步进度" : "同步窗口"}`;
  $("#create-button").classList.toggle("sync-active", running || interrupted);
  $("#sync-preview").hidden = hasJob;
  $("#sync-progress-section").hidden = !hasJob;
  $("#sync-reload").disabled = sync.loading || sync.starting;
  $("#sync-search").disabled = sync.loading || sync.starting;
  $("#sync-start").hidden = running && !sync.starting;
  $("#sync-start").disabled = sync.loading || sync.starting || (!hasJob && (!sync.previewId || !sync.selected.size));
  $("#sync-start").classList.toggle("is-loading", sync.starting);
  $("#sync-start").textContent = sync.starting ? "正在开始同步…" : interrupted ? "继续剩余同步" : hasJob ? "重新检测" : `开始同步 ${sync.selected.size} 个窗口`;
  $("#sync-cancel-job").hidden = !hasJob || (!running && !interrupted);
  $("#sync-cancel-job").disabled = sync.cancelling || (!interrupted && sync.cancelRequested);
  $("#sync-cancel-job").textContent = sync.cancelRequested && !interrupted ? "已请求取消" : sync.cancelling ? "正在请求取消…" : "取消剩余同步";
  $("#sync-retry-status").hidden = !sync.pollPaused || (!running && !interrupted);
  $("#sync-footer-note").textContent = running || interrupted ? "同步只添加新副本，不覆盖本地已有窗口" : "检测不复制资料；点击开始同步后仍须通过完整性检查";
  if (hasJob) renderSyncProgress();
  else {
    renderSyncCurrentProgress({});
    renderSyncPreview();
  }
}
function renderSyncPreview() {
  const sync = state.sync;
  const guidance = sourceGuidance();
  const ready = sync.preview.filter(syncCanImport);
  const imported = sync.preview.filter((item) => item.status === "already_imported").length;
  const terms = profileSearchTerms(sync.search);
  const tooManyTerms = terms.length > MAX_SEARCH_TERMS;
  const searchFeedback = $("#sync-search-feedback");
  searchFeedback.hidden = terms.length < 2;
  searchFeedback.classList.toggle("error", tooManyTerms);
  searchFeedback.textContent = tooManyTerms
    ? `最多支持 ${MAX_SEARCH_TERMS} 项，当前 ${terms.length} 项，请删减后搜索`
    : `批量搜索 ${terms.length} 项，匹配任意一项`;
  $("#sync-search").setAttribute("aria-invalid", String(tooManyTerms));
  const items = sync.preview.map((item, index) => ({ item, index })).filter(({ item }) => {
    if (tooManyTerms) return false;
    const text = `${item.name || ""} ${item.remark || ""} ${item.seq ?? ""}`.toLowerCase();
    return !terms.length || terms.some((term) => text.includes(term));
  });
  const pages = Math.max(1, Math.ceil(items.length / 50));
  sync.page = Math.min(Math.max(1, sync.page), pages);
  const offset = (sync.page - 1) * 50;
  const rows = items.slice(offset, offset + 50);
  $("#sync-preview-summary").textContent = sync.loading ? guidance.previewLoading :
    `本机候选 ${sync.preview.length} 个，可导入 ${ready.length} 个，已导入 ${imported} 个，暂不可导入 ${sync.preview.length - ready.length - imported} 个。${ready.length > SYNC_BATCH_LIMIT ? `每批最多 ${SYNC_BATCH_LIMIT} 个，剩余来源可在本批结束后重新预览同步。` : ""}`;
  $("#sync-preview-rows").innerHTML = rows.map(({ item, index }) => {
    const enabled = syncCanImport(item) && !sync.starting;
    const itemStatus = item.status === "ready" && item.has_local_data === false ? "missing_data" : item.status;
    const status = syncStatusLabels[itemStatus] || "暂不可导入";
    const reason = item.reason || (itemStatus === "source_open" ? guidance.sourceOpen : itemStatus === "already_imported" ? "保留已有本地副本，不重复、覆盖。" : itemStatus === "missing_data" ? guidance.missingData : "");
    const name = item.name || "未命名窗口";
    const remark = String(item.remark ?? "").trim();
    return `<tr><td class="select-cell"><input type="checkbox" data-sync-index="${index}" aria-label="选择 ${esc(name)}" ${enabled ? "" : "disabled"} ${sync.selected.has(item.source_key) ? "checked" : ""}></td><td><strong class="sync-source-name" title="${esc(name)}">${esc(name)}</strong><small>来源序号 ${esc(item.seq ?? "—")}${item.created_at ? ` · ${esc(displayDate(item.created_at))}` : ""}</small><small class="sync-source-remark" title="${esc(remark || "无备注")}">备注：${esc(remark || "—")}</small>${item.metadata_note ? `<small>${esc(item.metadata_note)}</small>` : ""}</td><td>${esc(item.os || "—")}<small>内核 ${esc(item.core_version || "—")}</small></td><td><span class="sync-status ${syncCanImport(item) ? "ready" : item.status === "already_imported" ? "muted" : "blocked"}">${status}</span>${reason ? `<small>${esc(reason)}</small>` : ""}</td></tr>`;
  }).join("");
  $("#sync-empty").hidden = sync.loading || rows.length > 0;
  $("#sync-empty").textContent = tooManyTerms ? `最多支持 ${MAX_SEARCH_TERMS} 项，请删减后搜索` : sync.search ? "没有符合条件的本机窗口。" : guidance.previewEmpty;
  const selectAll = $("#sync-select-all");
  selectAll.setAttribute("aria-label", `选择本批最多 ${SYNC_BATCH_LIMIT} 个可导入窗口`);
  selectAll.checked = ready.length > 0 && (ready.every((item) => sync.selected.has(item.source_key)) || (ready.length > SYNC_BATCH_LIMIT && sync.selected.size === SYNC_BATCH_LIMIT));
  selectAll.indeterminate = ready.some((item) => sync.selected.has(item.source_key)) && !selectAll.checked;
  selectAll.disabled = sync.loading || sync.starting || !ready.length;
  $("#sync-selection-count").textContent = `本批已选 ${sync.selected.size} 个可导入窗口（全部预览，每批最多 ${SYNC_BATCH_LIMIT} 个）${ready.length > SYNC_BATCH_LIMIT ? `；本批未选 ${Math.max(0, ready.length - sync.selected.size)} 个，可留待下批同步` : ""}`;
  $("#sync-range").textContent = `${items.length ? offset + 1 : 0}–${Math.min(offset + 50, items.length)} / ${items.length}`;
  $("#sync-page").textContent = `${sync.page} / ${pages}`;
  $("#sync-prev").disabled = sync.page <= 1 || sync.starting;
  $("#sync-next").disabled = sync.page >= pages || sync.starting;
}
function syncResultSummary(status) {
  return `成功 ${syncCount(status.completed)} 个，跳过 ${syncCount(status.skipped)} 个，失败 ${syncCount(status.failed)} 个。`;
}
function syncProgressNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}
function syncProgressPercent(done, total) {
  return Math.floor(Math.min(1, done / total) * 1000) / 10;
}
function syncProgressBytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value, unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++; }
  return `${Number(size.toFixed(unit ? 1 : 0))} ${units[unit]}`;
}
function syncProgressDuration(value) {
  const seconds = Math.floor(value);
  if (seconds < 60) return `${seconds} 秒`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`;
  return `${Math.floor(seconds / 3600)} 小时 ${Math.floor(seconds / 60) % 60} 分 ${seconds % 60} 秒`;
}
function renderSyncCurrentProgress(status) {
  const progress = status.state === "running" && status.progress && typeof status.progress === "object" && !Array.isArray(status.progress) ? status.progress : null;
  $("#sync-current").hidden = !progress;
  const bar = $("#sync-stage-progress");
  bar.removeAttribute("value");
  bar.max = 1;
  bar.setAttribute("aria-valuetext", "进度未知");
  for (const selector of ["#sync-current-label", "#sync-current-name", "#sync-stage-name", "#sync-stage-count", "#sync-stage-elapsed", "#sync-stage-timings"]) $(selector).textContent = "";
  $("#sync-current-name").title = "";
  $("#sync-stage-timings").hidden = true;
  if (!progress) return;
  const index = syncCount(progress.index), total = syncCount(status.total);
  const active = Array.isArray(status.active_items) ? status.active_items.length : 0;
  $("#sync-current-label").textContent = `${state.sync.pollPaused ? "上次读取 · " : ""}当前窗口${index ? ` ${index}${total ? ` / ${total}` : ""}` : ""}${active > 1 ? ` · 同时处理 ${active} 个窗口` : ""}`;
  const name = state.sync.names.get(progress.source_key) || (typeof progress.name === "string" && progress.name ? progress.name : "未命名窗口");
  $("#sync-current-name").textContent = name;
  $("#sync-current-name").title = name;
  $("#sync-stage-name").textContent = syncProgressPhases[progress.phase] || "正在处理窗口";
  const done = syncProgressNumber(progress.done), phaseTotal = syncProgressNumber(progress.total);
  const unit = ["bytes", "files", "steps"].includes(progress.unit) ? progress.unit : null;
  const measurable = unit && done !== null && phaseTotal !== null && phaseTotal > 0;
  const format = (value) => unit === "bytes" ? syncProgressBytes(value) : `${Math.floor(value)} ${unit === "files" ? "个文件" : "轮"}`;
  let detail = unit && done !== null ? `${format(done)}${phaseTotal !== null && phaseTotal > 0 ? ` / ${format(phaseTotal)}` : ""}` : "";
  if (measurable) {
    const percent = syncProgressPercent(done, phaseTotal);
    bar.max = phaseTotal;
    bar.value = Math.min(done, phaseTotal);
    detail += ` · ${percent}%`;
    bar.setAttribute("aria-valuetext", detail);
  } else {
    detail += `${detail ? " · " : ""}${phaseTotal === 0 ? "本阶段无可计量数据，等待确认" : "总量待确认"}`;
    bar.setAttribute("aria-valuetext", detail);
  }
  $("#sync-stage-count").textContent = detail;
  const elapsed = syncProgressNumber(progress.elapsed_seconds), phaseElapsed = syncProgressNumber(progress.phase_elapsed_seconds);
  $("#sync-stage-elapsed").textContent = [elapsed === null ? "" : `当前窗口已用 ${syncProgressDuration(elapsed)}`, phaseElapsed === null ? "" : `本阶段已用 ${syncProgressDuration(phaseElapsed)}`].filter(Boolean).join(" · ");
  const timings = progress.timings && typeof progress.timings === "object" ? progress.timings : {};
  const summary = Object.entries(syncProgressPhases).filter(([phase]) => phase !== progress.phase && syncProgressNumber(timings[phase]) !== null)
    .map(([phase, label]) => `${label} ${syncProgressDuration(timings[phase])}`).join(" · ");
  $("#sync-stage-timings").hidden = !summary;
  $("#sync-stage-timings").textContent = summary ? `已完成阶段耗时：${summary}` : "";
}
function renderSyncProgress() {
  const sync = state.sync;
  const status = sync.status || {};
  const running = syncRunning();
  const interrupted = syncInterrupted();
  const total = syncCount(status.total);
  const done = Math.min(total, syncCount(status.completed) + syncCount(status.skipped) + syncCount(status.failed));
  const phases = { preparing: "正在准备", preview: "正在检查资料", checking: "正在检查资料", copying: "正在复制浏览器资料", importing: "正在导入窗口", saving: "正在保存本地副本", finalizing: "正在完成同步" };
  const currentPhase = syncProgressPhases[status.progress?.phase] || syncProgressPhases[status.phase];
  const phaseLabel = currentPhase ? `${currentPhase}…` : phases[status.phase] || "正在同步窗口";
  $("#sync-phase").textContent = sync.pollPaused ? "进度读取已暂停" : interrupted ? "同步已中断，等待继续" : running ? (sync.cancelRequested ? "正在取消剩余同步" : phaseLabel) : status.state === "failed" ? "同步任务失败" : status.state === "cancelled" ? "同步已取消" : syncCount(status.failed) ? "同步完成，部分窗口失败" : "同步完成";
  $("#sync-progress-count").textContent = `批次已处理 ${done} / ${total} · ${total ? syncProgressPercent(done, total) : 0}%`;
  $("#sync-progress").max = Math.max(1, total);
  $("#sync-progress").value = done;
  $("#sync-progress-summary").textContent = syncResultSummary(status);
  renderSyncCurrentProgress(status);
  const note = interrupted ? "上次运行已中断，当前没有继续复制。可继续检查并同步剩余窗口，或取消剩余同步；已保存的副本会保留。" : running ? sync.cancelRequested ? "已开始的窗口会继续处理，只取消尚未开始的窗口。可关闭此面板，后台将继续更新结果。" : "可关闭此面板继续管理本地窗口；同步将在后台继续。" : "已导入的窗口是独立本地副本，来源后续改动或删除不会覆盖、删除它。";
  $("#sync-background-note").textContent = note + (sync.deferred ? ` 本批未选 ${sync.deferred} 个来源，本批结束后可重新预览，留待下批同步。` : "");
  const items = Array.isArray(status.items) ? status.items : [];
  $("#sync-result-list").innerHTML = items.slice(-100).map((item) =>
    `<div class="sync-result-item"><strong>${esc(item.name || sync.names.get(item.source_key) || "同步窗口")}</strong><span class="sync-status ${["completed", "imported", "success"].includes(item.status) ? "ready" : item.status === "failed" ? "blocked" : "muted"}">${syncStatusLabels[item.status] || "等待同步"}</span>${item.message ? `<small>${esc(item.message)}</small>` : ""}</div>`).join("") + (Math.max(items.length, syncCount(status.items_total)) > 100 ? `<p class="field-hint">显示最近 100 项；上方数量为本次全部结果。</p>` : "");
}
async function startSync() {
  const sync = state.sync;
  if (syncRunning() || sync.loading) return;
  if (syncInterrupted()) return resumeSyncJob();
  if (sync.jobId) return loadSyncPreview();
  if (sync.selected.size > SYNC_BATCH_LIMIT) {
    showSyncError(`单次最多同步 ${SYNC_BATCH_LIMIT} 个来源，请减少本批选择，其余来源留待下批同步。`);
    return;
  }
  const keys = sync.preview.filter((item) => syncCanImport(item) && sync.selected.has(item.source_key)).map((item) => item.source_key);
  if (!keys.length) return;
  if (keys.length > SYNC_BATCH_LIMIT) {
    showSyncError(`单次最多同步 ${SYNC_BATCH_LIMIT} 个来源，请重新预览并分批选择。`);
    return;
  }
  if (!sync.previewId) {
    showSyncError("请先重新检测可同步窗口，再点击开始同步。");
    return;
  }
  sync.deferred = sync.preview.filter(syncCanImport).length - keys.length;
  invalidateSyncStatus();
  sync.starting = true;
  showSyncError();
  renderSync();
  try {
    const result = await api("sync_windows", { source_keys: keys, preview_id: sync.previewId });
    if (!result?.job_id) throw new Error("本地服务未返回同步任务编号，请重新预览确认结果。");
    sync.jobId = String(result.job_id);
    sync.status = { state: "running", phase: "preparing", total: keys.length, completed: 0, skipped: 0, failed: 0, items: [] };
    sync.cancelRequested = false;
    sync.pollErrors = 0;
    sync.pollPaused = false;
  } catch (error) {
    showSyncError(error.message);
  } finally {
    invalidateSyncStatus();
    sync.starting = false;
    renderSync();
  }
  if (sync.jobId) pollSyncStatus();
}
async function resumeSyncJob() {
  const sync = state.sync;
  if (!syncInterrupted() || sync.starting || sync.cancelling) return;
  const jobId = sync.jobId;
  invalidateSyncStatus();
  sync.starting = true;
  showSyncError();
  renderSync();
  try {
    const result = await api("resume_sync", { job_id: jobId });
    if (String(result?.job_id || "") !== jobId) throw new Error("本地服务未确认继续任务，请读取进度确认结果。");
    sync.status = { ...sync.status, state: "running", phase: "preparing", progress: null, cancel_requested: false };
    sync.cancelRequested = false;
    sync.pollErrors = 0;
    sync.pollPaused = false;
  } catch {
    sync.pollPaused = true;
    showSyncError("继续请求未确认，任务可能已在运行。请继续读取进度确认结果。");
  } finally {
    invalidateSyncStatus();
    sync.starting = false;
    renderSync();
  }
  if (!sync.pollPaused) pollSyncStatus();
}
function scheduleSyncStatus(delay = 1000) {
  clearTimeout(state.sync.timer);
  if (syncRunning() && !state.sync.starting && !state.sync.cancelling && !state.sync.pollPaused) state.sync.timer = setTimeout(pollSyncStatus, delay);
}
async function pollSyncStatus() {
  const sync = state.sync;
  if (sync.polling || sync.starting || sync.cancelling || !sync.jobId || (!syncRunning() && !syncInterrupted())) return;
  sync.polling = true;
  const jobId = sync.jobId;
  const revision = sync.requestRevision;
  const current = () => jobId === sync.jobId && revision === sync.requestRevision;
  try {
    const status = await api("sync_status", { job_id: jobId, missing_ok: true });
    if (!current()) return;
    if (status === null) {
      clearSyncJob();
      await loadSyncPreview();
      return;
    }
    if (!status || !["running", "completed", "failed", "cancelled", "interrupted"].includes(status.state) || (status.job_id && String(status.job_id) !== jobId)) throw new Error("本地服务返回了无效的同步进度。");
    if (sync.status?.state === "cancelled" && status.state !== "cancelled") return;
    sync.status = boundedSyncStatus(status);
    sync.cancelRequested = sync.cancelRequested || Boolean(status.cancel_requested);
    sync.pollErrors = 0;
    showSyncError();
    renderSync();
    if (["completed", "failed", "cancelled"].includes(status.state) && sync.finishedJobId !== jobId) {
      sync.finishedJobId = jobId;
      try {
        await refreshProfiles();
      } catch {
        if (current()) showSyncError("同步任务已结束，但本地列表刷新失败。请关闭面板后刷新列表，不要重复导入。");
      }
      if (!current()) return;
      const summary = syncResultSummary(status);
      toast(`${status.state === "failed" ? "同步任务失败。" : "同步结束。"}${summary}`, status.state === "failed" || syncCount(status.failed) ? "error" : "success");
    }
  } catch {
    if (!current()) return;
    sync.pollErrors++;
    if (sync.pollErrors >= 3) {
      sync.pollPaused = true;
      showSyncError("暂时无法读取同步进度，任务可能仍在运行。请继续读取进度确认结果，不要重复开始同步。");
    }
    renderSync();
  } finally {
    sync.polling = false;
    scheduleSyncStatus(current() ? Math.min(5000, 1000 * Math.max(1, sync.pollErrors)) : 0);
  }
}
function resumeSyncStatus() {
  if (state.sync.starting || state.sync.cancelling) return;
  invalidateSyncStatus();
  state.sync.pollPaused = false;
  state.sync.pollErrors = 0;
  showSyncError();
  renderSync();
  pollSyncStatus();
}
async function cancelSyncJob() {
  const sync = state.sync;
  if ((!syncRunning() && !syncInterrupted()) || sync.starting || sync.cancelling || (sync.cancelRequested && !syncInterrupted())) return;
  const jobId = sync.jobId;
  const interrupted = syncInterrupted();
  invalidateSyncStatus();
  sync.cancelling = true;
  renderSync();
  try {
    await api("cancel_sync", { job_id: jobId });
    if (jobId !== sync.jobId) return;
    sync.cancelRequested = true;
    if (interrupted) {
      sync.status = { ...sync.status, state: "cancelled", phase: "finished", progress: null, cancel_requested: true };
      sync.pollPaused = false;
      clearTimeout(sync.timer);
    }
    showSyncError();
  } catch {
    sync.pollPaused = true;
    showSyncError("取消请求未确认，任务可能仍在运行。请继续查看进度，或稍后再试。");
  } finally {
    invalidateSyncStatus();
    sync.cancelling = false;
    renderSync();
  }
  if (syncRunning() && !sync.pollPaused) pollSyncStatus();
}

async function bootstrap({ quiet = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  const revision = ++state.statusRevision;
  const syncRevision = state.sync.requestRevision;
  const creationRevision = state.creation.revision;
  const settingsRevision = state.settingsRevision;
  const settingsDraftRevision = state.settingsDraftRevision;
  $("#refresh-button").disabled = true;
  try {
    const data = await api("bootstrap", { include_archived: true });
    const profilesCurrent = revision === state.statusRevision;
    acceptBootstrap(data, { preserveDrafts: quiet || !profilesCurrent || settingsDraftRevision !== state.settingsDraftRevision, syncRevision, creationRevision, profilesCurrent,
      settingsCurrent: settingsRevision === state.settingsRevision && !state.settingsSaving });
    setConnection(true);
    if (profilesCurrent) showServiceError("");
    if (profilesCurrent && !quiet && state.panel !== "profiles") renderPanel(state.panel);
  } catch (error) {
    if (revision !== state.statusRevision) return;
    setConnection(false);
    showServiceError(error.message);
  } finally {
    state.loading = false;
    $("#refresh-button").disabled = false;
    renderProfiles();
  }
}
function acceptBootstrap(data = {}, { preserveDrafts = true, syncRevision = state.sync.requestRevision, creationRevision = state.creation.revision, profilesCurrent = true, settingsCurrent = true } = {}) {
  if (profilesCurrent) {
    state.profiles = Array.isArray(data.profiles) ? data.profiles.filter((profile) => !state.deletedIds.has(String(profile.id))) : [];
    state.groups = Array.isArray(data.groups) ? data.groups : [];
    state.tags = Array.isArray(data.tags) ? data.tags : [];
  }
  state.cores = Array.isArray(data.cores) ? data.cores : [];
  state.defaults = mergedDefaults(data.defaults);
  state.capabilities = data.capabilities || {};
  renderSourceGuidance();
  if (data.settings && settingsCurrent) {
    state.settings = copy(data.settings);
    if (!preserveDrafts || (!state.settingsDirty && !state.settingsSaving)) {
      state.settingsDraft = copy(data.settings);
      state.settingsDirty = false;
    }
    state.settingsLoaded = true;
  }
  if (syncRevision === state.sync.requestRevision) {
    if (data.sync_job === null && state.sync.jobId && !state.sync.starting && !state.sync.cancelling) clearSyncJob();
    else restoreSyncJob(data.sync_job);
  }
  if (creationRevision === state.creation.revision && !state.creation.mutating && !state.saving && "creation_job" in data) acceptCreationJob(data.creation_job);
  pruneSelection();
  renderFilters();
  renderProfiles();
}
function mergedDefaults(value = {}) {
  return {
    ...copy(defaultProfile),
    ...copy(value),
    fingerprint: { ...defaultFingerprint, ...value?.fingerprint },
    preferences: { ...defaultProfile.preferences, ...value?.preferences },
    proxy: { ...defaultProfile.proxy, ...value?.proxy },
  };
}
async function refreshProfiles() {
  const revision = ++state.statusRevision;
  const data = await api("list", { include_archived: true });
  if (revision !== state.statusRevision) return;
  if (Array.isArray(data)) state.profiles = data.filter((profile) => !state.deletedIds.has(String(profile.id)));
  else if (Array.isArray(data?.profiles)) state.profiles = data.profiles.filter((profile) => !state.deletedIds.has(String(profile.id)));
  else throw new Error("本地服务未返回窗口列表。");
  if (Array.isArray(data?.groups)) state.groups = data.groups;
  if (Array.isArray(data?.tags)) state.tags = data.tags;
  pruneSelection();
  renderFilters();
  renderProfiles();
  if (["proxies", "recycle"].includes(state.panel)) renderPanel(state.panel);
}
function scheduleStatusRefresh(delay = 3000) {
  clearTimeout(state.statusTimer);
  if (document.hidden || !apiAvailable()) return;
  state.statusTimer = setTimeout(refreshStatus, delay);
}
async function refreshStatus() {
  if (state.statusRefreshing) return;
  if (
    document.hidden ||
    state.loading ||
    state.saving ||
    state.batchBusy ||
    state.operationIds.size
  ) {
    scheduleStatusRefresh();
    return;
  }
  state.statusRefreshing = true;
  const revision = state.statusRevision;
  try {
    const data = await api("status");
    if (revision !== state.statusRevision) return;
    const profiles = Array.isArray(data) ? data : data?.profiles;
    if (!Array.isArray(profiles)) throw new Error("未返回窗口运行状态。");
    let changed = false;
    let signatureChanged = false;
    let draftSignatureChanged = false;
    const profilesById = new Map(state.profiles.map((profile) => [String(profile.id), profile]));
    for (const update of profiles) {
      const profile = profilesById.get(String(update.id));
      if (!profile || state.operationIds.has(String(update.id))) continue;
      for (const key of ["status", "is_running", "last_opened_at", "signature_status", "signature_expires_at", "signature_provider", "config_status", "delete_pending"]) {
        if (Object.hasOwn(update, key) && key.startsWith("signature_") && String(state.draft?.id) === String(update.id) && state.draft[key] !== update[key]) {
          state.draft[key] = update[key];
          draftSignatureChanged = true;
        }
        if (Object.hasOwn(update, key) && profile[key] !== update[key]) {
          profile[key] = update[key];
          changed = true;
          if (key.startsWith("signature_") || key === "config_status" || key === "delete_pending") signatureChanged = true;
        }
      }
    }
    if (draftSignatureChanged && state.draft) $$('[data-signature-notice]').forEach((notice) => { notice.textContent = signatureNoticeText(state.draft); });
    if (signatureChanged) renderProfiles();
    else if (changed) updateRunningIndicators();
    if (changed && state.panel === "recycle") renderRecycle();
  } catch {
    // A transient status failure must not discard local edits or show repeated alerts.
  } finally {
    state.statusRefreshing = false;
    scheduleStatusRefresh();
  }
}
function updateRunningIndicators() {
  const active = state.profiles.filter((profile) => !isArchived(profile));
  $("#count-running").textContent = active.filter(isRunning).length;
  const focused = document.activeElement;
  if (state.filter === "running") {
    if (!$("#profile-rows").contains(focused)) {
      renderProfiles();
      return;
    }
    state.profileRenderPending = true;
  }
  $$("#profile-rows > tr").forEach((row) => {
    const profile = profileById(row.dataset.id);
    if (!profile) return;
    const button = $(".open-button", row);
    if (button) updateOpenButton(button, profile);
    const time = $("[data-last-opened]", row);
    if (time) time.textContent = displayDate(profile.last_opened_at);
  });
}
function updateOpenButton(button, profile) {
  const running = isRunning(profile);
  const deletionPending = isDeletePending(profile);
  const action = state.operationActions.get(String(profile.id));
  const pending = deletionPending || state.operationIds.has(String(profile.id)) ||
    ["opening", "closing"].includes(profile.status);
  const label = deletionPending ? "删除未完成" : action === "open" || profile.status === "opening"
    ? "检测代理并打开…"
    : action === "close" || profile.status === "closing"
      ? "正在关闭"
      : pending ? "处理中" : running ? "已打开" : "打开";
  button.classList.toggle("running", running);
  button.dataset.action = running ? "activate" : "open";
  button.disabled = pending;
  button.innerHTML = `${svg(running ? "windows" : "play")}${label}`;
}
function pruneSelection() {
  const existing = new Set(
    state.profiles.filter((p) => !isArchived(p)).map((p) => String(p.id)),
  );
  for (const id of state.selected)
    if (!existing.has(id)) state.selected.delete(id);
  const archived = new Set(state.profiles.filter(isArchived).map((p) => String(p.id)));
  for (const id of state.recycleSelected)
    if (!archived.has(id)) state.recycleSelected.delete(id);
}
function renderFilters() {
  const groups = [
    ...new Set([
      ...state.groups,
      ...state.profiles.map((p) => p.group).filter(Boolean),
    ]),
  ];
  const tags = [
    ...new Set([
      ...state.tags,
      ...state.profiles.flatMap((p) => (Array.isArray(p.tags) ? p.tags : [])),
    ]),
  ];
  const replace = (selector, values, empty, current) => {
    $(selector).innerHTML =
      `<option value="">${empty}</option>` +
      values
        .map(
          (value) =>
            `<option value="${esc(value)}" ${value === current ? "selected" : ""}>${esc(value)}</option>`,
        )
        .join("");
  };
  replace("#group-filter", groups, "全部分组", state.group);
  replace("#tag-filter", tags, "全部标签", state.tag);
}
const MAX_SEARCH_TERMS = 10;
const profileCollator = new Intl.Collator("zh-CN", { numeric: true });
let profileSearchTimer = null;
let profileSearchRevision = 0;
let profileSearchComposing = false;
function cancelProfileSearch() {
  clearTimeout(profileSearchTimer);
  profileSearchTimer = null;
  profileSearchRevision++;
}
function applyProfileSearch() {
  cancelProfileSearch();
  // Keep the applied query and visible rows together while input is pending.
  state.search = $("#search-input").value.trim();
  state.page = 1;
  renderProfiles();
}
function scheduleProfileSearch(event) {
  const input = event.target;
  input.rows = Math.min(4, Math.max(1, input.value.split(/\r\n|\r|\n/).length));
  cancelProfileSearch();
  if (profileSearchComposing || event.isComposing) return;
  if (!input.value.trim()) {
    applyProfileSearch();
    return;
  }
  const revision = profileSearchRevision;
  profileSearchTimer = setTimeout(() => {
    if (revision === profileSearchRevision) applyProfileSearch();
  }, 150);
}
function profileSearchTerms(value) {
  return [...new Set(String(value).split(/[\r\n,，;；]+/)
    .map((term) => term.trim().toLowerCase()).filter(Boolean))];
}
function filteredProfiles() {
  const terms = profileSearchTerms(state.search);
  if (terms.length > MAX_SEARCH_TERMS) return [];
  const searches = terms.map((term) => terms.length > 1 && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(term)
    ? new RegExp(`(^|[^\\d.])${term.replace(/\./g, "\\.")}(?![\\d.])`)
    : term);
  return state.profiles
    .filter((p) => !isArchived(p))
    .filter((p) => state.filter !== "running" || isRunning(p))
    .filter((p) => !state.group || p.group === state.group)
    .filter((p) => !state.tag || (p.tags || []).includes(state.tag))
    .filter((p) => {
      if (!terms.length) return true;
      const text = [
          p.name,
          p.seq,
          p.remark,
          p.group,
          p.proxy?.host,
          p.proxy?.port,
          ...(p.tags || []),
        ]
          .join(" ")
          .toLowerCase();
      return searches.some((search) => typeof search === "string" ? text.includes(search) : search.test(text));
    })
    .sort((a, b) => {
      let av = a[state.sort] ?? "",
        bv = b[state.sort] ?? "";
      if (state.sort === "seq")
        return (Number(av) - Number(bv)) * state.direction;
      return (
        profileCollator.compare(String(av), String(bv)) *
        state.direction
      );
    });
}
function renderProfiles() {
  clearTimeout(state.profileFocusTimer);
  state.profileFocusTimer = null;
  state.profileRenderPending = false;
  const terms = profileSearchTerms(state.search);
  const tooManyTerms = terms.length > MAX_SEARCH_TERMS;
  const searchFeedback = $("#search-feedback");
  searchFeedback.hidden = terms.length < 2;
  searchFeedback.classList.toggle("error", tooManyTerms);
  searchFeedback.textContent = tooManyTerms
    ? `最多支持 ${MAX_SEARCH_TERMS} 项，当前 ${terms.length} 项，请删减后搜索`
    : `批量搜索 ${terms.length} 项，匹配任意一项`;
  $("#search-input").setAttribute("aria-invalid", String(tooManyTerms));
  const active = state.profiles.filter((p) => !isArchived(p));
  const list = filteredProfiles();
  const maxPage = Math.max(1, Math.ceil(list.length / state.pageSize));
  state.page = Math.min(Math.max(1, state.page), maxPage);
  const start = (state.page - 1) * state.pageSize;
  const rows = list.slice(start, start + state.pageSize);
  $("#total-count").textContent = active.length;
  $("#count-all").textContent = active.length;
  $("#count-running").textContent = active.filter(isRunning).length;
  $("#archived-count").textContent = state.profiles.filter(isArchived).length;
  $("#profile-rows").innerHTML = rows.map((p) => profileRow(p)).join("");
  $$("#profile-rows .row-check").forEach((control) => { control.disabled = state.deleteBusy; });
  $("#empty-state").hidden = rows.length > 0;
  const filtered = Boolean(
    state.search || state.group || state.tag || state.filter === "running",
  );
  $("#empty-state h3").textContent = tooManyTerms ? "搜索项超过上限" : filtered
    ? "没有符合条件的窗口"
    : "暂无浏览器窗口";
  $("#empty-state p").textContent = tooManyTerms ? `最多支持 ${MAX_SEARCH_TERMS} 项，请删减后搜索` : filtered
    ? "尝试更换筛选条件，或重置筛选"
    : state.capabilities.create_windows ? "点击“新建窗口”创建本地窗口，或点击“同步窗口”导入本机来源" : sourceGuidance().listEmpty;
  $("#selected-count").textContent = state.selected.size;
  $$("[data-batch]").forEach(
    (button) => (button.disabled = state.batchBusy || state.deleteBusy || state.selected.size === 0 || (button.dataset.batch === "open" && active.some((profile) => state.selected.has(String(profile.id)) && isDeletePending(profile)))),
  );
  $("#clear-selection").disabled = state.deleteBusy || state.selected.size === 0;
  const selectAll = $("#select-all");
  selectAll.checked =
    rows.length > 0 && rows.every((p) => state.selected.has(String(p.id)));
  selectAll.indeterminate =
    rows.some((p) => state.selected.has(String(p.id))) && !selectAll.checked;
  selectAll.disabled = state.deleteBusy || !rows.length;
  $("#page-label").textContent = `${state.page} / ${maxPage}`;
  $("#range-label").textContent =
    `${list.length ? start + 1 : 0}–${Math.min(start + state.pageSize, list.length)} / ${list.length}`;
  $("#prev-page").disabled = state.page <= 1;
  $("#next-page").disabled = state.page >= maxPage;
}
function profileRow(p) {
  const id = esc(p.id);
  const running = isRunning(p);
  const deletionPending = isDeletePending(p);
  const pending =
    deletionPending || state.operationIds.has(String(p.id)) ||
    ["opening", "closing"].includes(p.status);
  const actionLabel =
    deletionPending ? "删除未完成" : state.operationActions.get(String(p.id)) === "open" || p.status === "opening"
      ? "检测代理并打开…"
      : p.status === "closing"
        ? "正在关闭"
        : pending
          ? "处理中"
          : running
            ? "已打开"
            : "打开";
  const proxy = p.proxy || {};
  const system = String(p.fingerprint?.os || p.os || "");
  const osIcon = /mac|ios/i.test(system)
    ? "apple"
    : /linux/i.test(system)
      ? "linux"
      : "windows";
  const proxyText =
    proxy.type && proxy.type !== "noproxy"
      ? `${proxy.host || "未设置"}${proxy.port ? ":" + proxy.port : ""}`
      : "本机网络";
  const status =
    deletionPending ? " · 删除未完成" : p.config_status === "expired"
      ? p.signature_provider === "local-v1" ? " · 本地启动配置待维护" : " · 启动签名已到期"
      : p.config_status === "draft"
      ? " · 待生成"
      : p.config_status === "error"
        ? " · 配置异常"
        : "";
  const editCell = (action, label) => `<button class="cell-edit-button" data-action="${action}" data-id="${id}" title="编辑${label}" aria-label="编辑${label}：${esc(p.name || "未命名窗口")}" ${deletionPending ? "disabled" : ""}>${svg("edit")}</button>`;
  return `<tr data-id="${id}" class="${state.selected.has(String(p.id)) ? "selected" : ""}"><td class="select-cell"><input class="row-check" type="checkbox" data-id="${id}" aria-label="选择 ${esc(p.name)}" ${state.selected.has(String(p.id)) ? "checked" : ""}></td><td>${esc(p.seq ?? "—")}</td><td><span class="group-chip">${esc(p.group || "未分组")}</span></td><td><button class="profile-name" data-action="edit" data-id="${id}" title="${esc(p.name)}">${esc(p.name || "未命名窗口")}</button><div class="profile-id">${p.source_seq != null && p.source_seq !== "" ? `来自比特 #${esc(p.source_seq)}` : "本地环境"}${esc(status)}</div></td><td title="${esc(proxyText)}"><div class="editable-cell"><div class="cell-value"><span class="proxy-value">${esc(proxyText)}</span><span class="proxy-type">${esc(proxy.type && proxy.type !== "noproxy" ? proxy.type.toUpperCase() : "不使用代理")}</span></div>${editCell("proxy", "代理")}</div></td><td><div class="editable-cell"><div class="cell-value">${(
    p.tags || []
  )
    .slice(0, 2)
    .map((tag) => `<span class="tag-chip">${esc(tag)}</span>`)
    .join(
      "",
    )}${(p.tags || []).length > 2 ? `<span class="muted">+${p.tags.length - 2}</span>` : ""}${!(p.tags || []).length ? "—" : ""}</div>${editCell("tags", "标签")}</div></td><td title="${esc(p.remark || "")}"><div class="editable-cell"><span class="cell-value">${esc(p.remark || "—")}</span>${editCell("remark", "备注")}</div></td><td><span class="time-text">${esc(displayDate(p.created_at))}</span></td><td><span class="os-icon" title="${esc(system || "Windows")}">${svg(osIcon)}</span></td><td class="actions-cell"><div class="row-actions"><button class="open-button ${running ? "running" : ""}" data-action="${running ? "activate" : "open"}" data-id="${id}" ${pending ? "disabled" : ""}>${svg(running ? "windows" : "play")}${actionLabel}</button><button class="menu-button" data-action="menu" data-id="${id}" aria-label="${esc(p.name)} 的更多操作" aria-haspopup="menu">⋮</button></div></td><td><span class="time-text" data-last-opened>${esc(displayDate(p.last_opened_at))}</span></td></tr>`;
}

async function navigate(panel) {
  if (state.panel === panel) return;
  if (state.panel === "groups" && state.groupsSaving) return;
  if (state.panel === "settings" && state.settingsSaving) return;
  if (
    state.panel === "groups" &&
    JSON.stringify(state.groupDraft) !== JSON.stringify(state.groupOriginal) &&
    !(await confirmAction(
      "未保存的分组",
      "分组修改尚未保存，确认离开吗？",
      "离开",
    ))
  )
    return;
  if (state.panel === "settings" && state.settingsDirty) {
    if (!(await confirmAction(
      "未保存的设置",
      "设置修改尚未保存，确认离开吗？",
      "离开",
    ))) return;
    state.settingsDraft = copy(state.settings);
    state.settingsDirty = false;
    state.settingsDraftRevision++;
  }
  state.panel = panel;
  $$(".panel").forEach((el) =>
    el.classList.toggle("active", el.id === `panel-${panel}`),
  );
  $$(".nav-item").forEach((el) =>
    el.classList.toggle("active", el.dataset.panel === panel),
  );
  $("#recycle-nav").classList.toggle("active", panel === "recycle");
  const titles = {
    profiles: ["浏览器窗口", "同步并管理独立的本机浏览器副本"],
    groups: ["分组管理", "按用途整理本机窗口"],
    proxies: ["代理配置", "查看并检测窗口代理"],
    settings: ["设置", "管理本地运行与数据选项"],
    help: ["使用说明", "快速了解本地窗口管理"],
    recycle: ["回收站", "恢复已经归档的本机窗口"],
  };
  $("#page-title").textContent = titles[panel][0];
  $("#page-subtitle").textContent = titles[panel][1];
  await renderPanel(panel);
}
async function renderPanel(panel) {
  if (panel === "groups") {
    state.groupDraft = [...state.groups];
    state.groupOriginal = [...state.groups];
    state.groupSources = [...state.groups];
    renderGroups();
  } else if (panel === "proxies") renderProxies();
  else if (panel === "recycle") renderRecycle();
  else if (panel === "settings") await loadSettings();
}
function renderGroups() {
  $("#group-list").innerHTML = state.groupDraft.length
    ? state.groupDraft
        .map(
          (group, index) =>
            `<div class="group-row">${svg("folder")}<input type="text" data-group-index="${index}" value="${esc(group)}" placeholder="请输入分组名称" aria-label="分组名称"><span class="group-count">${state.profiles.filter((p) => p.group === state.groupSources[index] && !isArchived(p)).length} 个窗口</span><button class="text-button danger-text" data-remove-group="${index}">移除</button></div>`,
        )
        .join("")
    : '<div class="plain-empty">暂无分组，点击“新增分组”开始整理窗口。</div>';
}
function normalizeGroupName(value) {
  // Match Python str.strip() and its Unicode code-point length limit.
  const strip = (name) => name.replace(/^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu, "");
  return strip(Array.from(strip(String(value))).slice(0, 100).join(""));
}
async function saveGroups() {
  if (state.groupsSaving) return;
  const groups = state.groupDraft.map(normalizeGroupName);
  if (groups.some((group) => !group))
    return toast("分组名称不能为空。", "error");
  if (new Set(groups).size !== groups.length)
    return toast("分组名称不能重复。", "error");
  const button = $("#save-groups");
  state.groupsSaving = true;
  button.disabled = true;
  $("#group-list").inert = true;
  $("#add-group").disabled = true;
  try {
    const renames = Object.fromEntries(
      state.groupSources
        .map((old, index) => [old, groups[index]])
        .filter(([old, value]) => old && value && old !== value),
    );
    const result = await api("groups_save", { groups, renames });
    const savedGroups = Array.isArray(result?.groups) ? result.groups : groups;
    const existingGroups = new Set(savedGroups);
    for (const profile of state.profiles) {
      const old = profile.group || "";
      const next = Object.hasOwn(renames, old) ? renames[old] : old;
      profile.group = existingGroups.has(next) ? next : "";
    }
    state.groups = [...savedGroups];
    const filteredGroup = Object.hasOwn(renames, state.group) ? renames[state.group] : state.group;
    state.group = existingGroups.has(filteredGroup) ? filteredGroup : "";
    state.groupDraft = [...savedGroups];
    state.groupOriginal = [...savedGroups];
    state.groupSources = [...savedGroups];
    renderFilters();
    renderGroups();
    renderProfiles();
    toast("分组已保存。", "success");
    try {
      await refreshProfiles();
    } catch (error) {
      showServiceError(`分组已保存，但列表刷新失败：${error.message}`);
    }
  } catch (error) {
    toast(error.message, "error");
  } finally {
    state.groupsSaving = false;
    button.disabled = false;
    $("#group-list").inert = false;
    $("#add-group").disabled = false;
  }
}
function renderProxies() {
  const profiles = state.profiles.filter((p) => !isArchived(p));
  $("#proxy-list").innerHTML = profiles.length
    ? profiles
        .map((p) => {
          const proxy = p.proxy || {};
          return `<div class="proxy-item"><div class="proxy-symbol">${svg("globe")}</div><div class="proxy-info"><h3>${esc(p.name || "未命名窗口")}</h3><p>${esc(proxy.type && proxy.type !== "noproxy" ? `${proxy.type.toUpperCase()} · ${proxy.host || "未设置"}${proxy.port ? ":" + proxy.port : ""}` : "不使用代理 · 本机网络")}</p><p class="proxy-result" data-proxy-result="${esc(p.id)}"></p></div><button class="button small" data-proxy-edit="${esc(p.id)}">编辑代理</button><button class="button small" data-proxy-test="${esc(p.id)}">检测连接</button></div>`;
        })
        .join("")
    : '<div class="plain-empty">暂无窗口代理。同步窗口后可在这里查看并检测。</div>';
}
function renderRecycle() {
  const rows = state.profiles.filter(isArchived);
  const busy = state.batchBusy || state.deleteBusy;
  const selectAll = $("#recycle-select-all");
  selectAll.disabled = busy || !rows.length;
  selectAll.checked = rows.length > 0 && rows.every((p) => state.recycleSelected.has(String(p.id)));
  selectAll.indeterminate = !selectAll.checked && rows.some((p) => state.recycleSelected.has(String(p.id)));
  $("#recycle-selected-count").textContent = state.recycleSelected.size;
  $("#recycle-delete-selected").disabled = busy || !state.recycleSelected.size;
  $("#recycle-list").innerHTML = rows.length
    ? rows
        .map(
          (p) =>
            `<div class="recycle-item"><input type="checkbox" data-recycle-select="${esc(p.id)}" aria-label="选择 ${esc(p.name || "未命名窗口")}" ${state.recycleSelected.has(String(p.id)) ? "checked" : ""} ${busy ? "disabled" : ""}><div class="proxy-symbol">${svg("windows")}</div><div class="recycle-info"><h3>${esc(p.name || "未命名窗口")}${isDeletePending(p) ? " · 删除未完成" : ""}</h3><p>序号 ${esc(p.seq ?? "—")} · ${esc(p.group || "未分组")} · 创建于 ${esc(displayDate(p.created_at))}</p></div><button class="button small" data-restore="${esc(p.id)}" ${busy || isDeletePending(p) || state.operationIds.has(String(p.id)) ? "disabled" : ""}>${svg("restore")}恢复窗口</button><button class="button small danger-text" data-delete="${esc(p.id)}" ${busy || state.operationIds.has(String(p.id)) ? "disabled" : ""}>${svg("trash")}删除</button></div>`,
        )
        .join("")
    : '<div class="plain-empty">回收站为空<br>移至回收站的窗口会显示在这里。</div>';
}

async function loadSettings() {
  const revision = state.settingsRevision;
  const draftRevision = state.settingsDraftRevision;
  const request = ++state.settingsReadRequest;
  const current = () => request === state.settingsReadRequest && revision === state.settingsRevision && !state.settingsSaving;
  const edited = () => draftRevision !== state.settingsDraftRevision || state.settingsDirty;
  try {
    const data = await api("settings_get");
    if (!current()) return;
    state.settings = copy(data?.settings || data || {});
    state.settingsLoaded = true;
    if (edited()) return;
    state.settingsDraft = copy(state.settings);
    state.settingsDirty = false;
    renderSettings();
  } catch (error) {
    if (!current()) return;
    if (edited()) { toast(error.message, "error"); return; }
    $("#settings-form").innerHTML =
      `<div class="inline-error">${esc(error.message)}</div>`;
    $("#save-settings").disabled = true;
  }
}
function renderSettings() {
  const settings = state.settingsDraft;
  $("#save-settings").disabled = state.settingsSaving;
  $("#settings-form").innerHTML =
    `<div class="settings-fields"><div class="form-grid"><div class="field full"><label class="field-label" for="settings-browser_path">浏览器内核路径 ${help("仅支持与此程序兼容的本机浏览器内核，由本地服务验证路径。")}</label><div class="path-control"><input id="settings-browser_path" data-setting="browser_path" value="${esc(settings.browser_path || "")}" placeholder="留空使用程序自动发现的内核"><button class="button" data-choose="browser_path" type="button">选择文件</button></div><div class="field-hint">留空时自动发现兼容内核；手动路径须指向有效的浏览器程序。</div></div><div class="field full"><label class="field-label" for="settings-download_dir">默认下载目录</label><div class="path-control"><input id="settings-download_dir" data-setting="download_dir" value="${esc(settings.download_dir || "")}" placeholder="使用浏览器默认下载目录"><button class="button" data-choose="download_dir" type="button">选择文件夹</button></div></div><div class="field full"><label class="field-label" for="settings-start_page">默认启动网址</label><input id="settings-start_page" data-setting="start_page" value="${esc(settings.start_page || "")}" placeholder="about:blank"><div class="field-hint">窗口未配置启动网址时使用。</div></div><div class="field"><label class="field-label" for="settings-close_behavior">退出程序时</label><select id="settings-close_behavior" data-setting="close_behavior"><option value="keep_browsers" ${settings.close_behavior !== "close_browsers" ? "selected" : ""}>保留已打开的浏览器</option><option value="close_browsers" ${settings.close_behavior === "close_browsers" ? "selected" : ""}>关闭由程序打开的浏览器</option></select></div><div class="field"><label class="field-label">窗口关闭确认</label><label class="checkbox-field"><input type="checkbox" data-setting="confirm_close" ${settings.confirm_close !== false ? "checked" : ""}>关闭浏览器前确认 ${help("手动或批量关闭浏览器时显示确认提示。")}</label></div></div></div>`;
}
async function saveSettings() {
  if (state.settingsSaving) return;
  const button = $("#save-settings");
  const draft = state.settingsDraft;
  const snapshot = copy(draft);
  state.settingsSaving = true;
  state.settingsRevision++;
  button.disabled = true;
  try {
    const result = await api("settings_save", { settings: snapshot });
    state.settings = copy(result?.settings || snapshot);
    state.settingsLoaded = true;
    if (state.settingsDraft === draft) {
      state.settingsDirty = JSON.stringify(draft) !== JSON.stringify(snapshot);
      if (!state.settingsDirty) state.settingsDraft = copy(state.settings);
    }
    toast("本地设置已保存。", "success");
  } catch (error) {
    toast(error.message, "error");
  } finally {
    state.settingsSaving = false;
    state.settingsRevision++;
    button.disabled = false;
  }
}
async function chooseSetting(key, button) {
  const draft = state.settingsDraft;
  button.disabled = true;
  try {
    const data = await api(
      key === "download_dir" ? "choose_folder" : "choose_file",
      { purpose: key },
    );
    const path = typeof data === "string" ? data : data?.path;
    if (path && state.settingsDraft === draft && state.panel === "settings") {
      draft[key] = path;
      state.settingsDirty = true;
      state.settingsDraftRevision++;
      $("#settings-" + key).value = path;
    }
  } catch (error) {
    toast(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function help(text) {
  return `<span class="help-dot" tabindex="0" title="${esc(text)}" aria-label="${esc(text)}">?</span>`;
}
function fieldText(value, type, lines = false) {
  if (type?.startsWith("json") && typeof value === "object" && value !== null)
    return JSON.stringify(value, null, 2);
  if (Array.isArray(value)) return value.join(type === "lines" || lines ? "\n" : ",");
  return value ?? "";
}
function field(path, label, type = "text", options = {}) {
  const value = getPath(state.draft, path);
  const id = `field-${path.replaceAll(".", "-")}`;
  const required = options.required ? '<span class="required">*</span>' : "";
  const info = options.help ? help(options.help) : "";
  let control = "";
  if (type === "checkbox")
    control = `<label class="checkbox-field"><input type="checkbox" id="${id}" data-field="${path}" data-type="boolean" ${value === true || value === 1 || value === "1" || value === "true" ? "checked" : ""}>${esc(options.text || "启用")}${info}</label>`;
  else if (type === "select") {
    const choices = options.options || [];
    const stringValue = String(value ?? "");
    const exists = choices.some(
      (choice) =>
        String(Array.isArray(choice) ? choice[0] : choice) === stringValue,
    );
    const normalized =
      exists || !stringValue
        ? choices
        : [[stringValue, stringValue], ...choices];
    control = `<select id="${id}" data-field="${path}" data-type="${options.valueType || "string"}">${normalized
      .map((choice) => {
        const [key, text] = Array.isArray(choice) ? choice : [choice, choice];
        return `<option value="${esc(key)}" ${String(key) === stringValue ? "selected" : ""}>${esc(text)}</option>`;
      })
      .join("")}</select>`;
  } else if (type === "textarea") {
    const text = fieldText(value, options.valueType, options.lines);
    control = `<textarea id="${id}" data-field="${path}" data-type="${options.valueType || "string"}" ${options.class ? `class="${options.class}"` : ""} rows="${options.rows || 3}" placeholder="${esc(options.placeholder || "")}" ${options.maxLength ? `maxlength="${options.maxLength}"` : ""}>${esc(text)}</textarea>`;
  } else {
    const text = Array.isArray(value) ? value.join(",") : value;
    control = `<div class="field-control"><input id="${id}" type="${type}" data-field="${path}" data-type="${options.valueType || (type === "number" ? "number" : "string")}" value="${esc(text)}" placeholder="${esc(options.placeholder || "")}" ${options.min !== undefined ? `min="${options.min}"` : ""} ${options.max !== undefined ? `max="${options.max}"` : ""} ${options.step ? `step="${options.step}"` : ""} ${type === "password" ? 'autocomplete="new-password" data-secret="true"' : ""}>${type === "password" ? `<button class="reveal-button" type="button" data-reveal="${id}" aria-label="显示或隐藏${esc(label)}">${svg("eye")}</button>` : ""}</div>`;
  }
  return `<div class="field ${options.full ? "full" : ""}"><label class="field-label" for="${id}">${required}${esc(label)}${type !== "checkbox" ? info : ""}</label>${control}${options.hint ? `<div class="field-hint">${esc(options.hint)}</div>` : ""}</div>`;
}
function fp(path, label, type, options = {}) {
  return field(`fingerprint.${path}`, label, type, options);
}
const noiseOptions = [
  ["0", "噪声"],
  ["1", "真实"],
];
function updateFingerprintReadOnly() {
  const compatibilityFields = ["fingerprint.version", "fingerprint.osVersion", "fingerprint.timeZoneOffset"];
  const systemResolution = String(state.draft?.fingerprint?.resolutionType) === "0";
  $$("[data-form-section='fingerprint'] input,[data-form-section='fingerprint'] select,[data-form-section='fingerprint'] textarea", $("#profile-form")).forEach((control) => {
    control.disabled = !state.creatingDraft || compatibilityFields.includes(control.dataset?.field) ||
      (systemResolution && control.dataset?.field === "fingerprint.devicePixelRatio");
  });
}
function signatureNoticeText(profile) {
  if (profile?.signature_provider === "local-v1" && profile?.environment_check) {
    const firstEnrollment = Array.isArray(profile.import_notes) && profile.import_notes.includes("原厂未保留历史运行种子，使用对应版本公开签名种子首次登记");
    return "独立本地启动：保留原环境，开窗前核对已登记信号；发现变化会阻止账号窗口打开。指定代理故障时不回退直连。" + (firstEnrollment ? " 原厂未保留历史运行种子，本次已首次固定对应版本种子；无法保证还原更早一次运行的全部状态。" : "");
  }
  if (profile?.signature_provider === "local-v1") return "独立本地启动：环境沿用迁移快照，签名由本机维护，无需比特客户端、原厂授权或联网。原有代理检测规则保持不变。";
  if (!profile?.signature_status) return "";
  if (!profile.signature_expires_at) return "原厂启动签名有效期无法确认，不能保证正常打开；请保留现有资料和配置。";
  return `原厂启动签名${profile.signature_status === "expired" ? "已到期" : "有效至"}：${displayDate(profile.signature_expires_at)}。更换代理不需要重签，但不会延长现有签名的有效期；本版不能保证永久离线运行。`;
}
function buildProfileForm() {
  const lifetimeNotice = state.draft?.signature_status
    ? `<div class="info-banner" data-signature-notice>${esc(signatureNoticeText(state.draft))}</div>`
    : "";
  const creationFields = state.creatingDraft ? `<div class="form-grid">${field("creation.count", "创建数量", "number", { min: 1, max: 1000, help: "单个或批量创建，最多1000个。批量名称按前缀追加序号。" })}${field("creation.random_each", "批量指纹", "checkbox", { text: "每个窗口使用不同随机指纹", help: "关闭时所有窗口使用当前表单指纹；各窗口的资料和加密密钥仍独立。" })}${field("creation.proxy_lines", "批量代理", "textarea", { valueType: "lines", full: true, rows: 3, help: "留空使用代理设置；1行共用或每个窗口1行，支持现有代理格式。" })}</div><div class="form-divider"></div>` : "";
  const basic = `${creationFields}<div class="form-intro"><div><h3>基础设置</h3><p>为窗口设置独立的名称和使用信息</p></div></div><div class="form-grid">${field("name", "窗口名称", "text", { required: true, placeholder: "请输入窗口名称" })}${field("group", "分组", "select", { options: [["", "未分组"], ...state.groups.map((group) => [group, group])], help: "分组可在左侧“分组管理”中添加或修改。" })}${field("tags", "标签", "text", { valueType: "list", placeholder: "输入标签，使用逗号分隔", help: "同一窗口可以设置多个标签。" })}${field("platform", "账号平台", "text", { placeholder: "例如：自定义平台名称" })}${field("username", "账号 / 用户名", "text", { placeholder: "可选，仅保存在本机" })}${field("password", "账号密码", "password", { placeholder: "请输入账号密码" })}${field("duplicate_check", "重复校验", "checkbox", { text: "校验重复窗口信息", help: "保存时由本地服务校验重复配置。" })}${field("fa_secret", "2FA 密钥", "password", { placeholder: "可选，双重验证密钥", help: "仅在本地保存；请妥善管理。" })}${field("allow_multi_open", "多开设置", "checkbox", { text: "保留多开兼容设置", help: "不同窗口使用独立资料可同时运行，同一资料再次打开会前置。此选项仅保留兼容值。" })}${field("remark", "备注", "textarea", { placeholder: "为窗口添加备注", rows: 3, full: true })}${field("urls", "启动网址", "textarea", { placeholder: "每行一个网址，例如 https://example.com", valueType: "lines", lines: true, full: true, hint: "打开窗口时按顺序访问；留空使用默认启动页。", rows: 3 })}</div>`;
  const proxy = `${lifetimeNotice}<div class="form-intro"><div><h3>代理设置</h3><p>本地独立代理，修改无需比特签名；请先关闭窗口再修改，重新打开后生效。</p></div></div><div class="form-grid">${field(
    "proxy.type",
    "代理类型",
    "select",
    {
      options: [
        ["noproxy", "不使用代理"],
        ["http", "HTTP"],
        ["https", "HTTPS"],
        ["socks5", "SOCKS5"],
        ["ssh", "SSH"],
      ],
    },
  )}${field("proxy.host", "代理主机", "text", { placeholder: "主机名 / IP，或粘贴完整代理自动分填", help: "支持协议地址、主机:端口:用户名:密码，以及竖线分隔格式。未带协议时沿用当前代理类型。", hint: "可直接粘贴完整代理；尾部到期信息会自动忽略。" })}${field("proxy.port", "代理端口", "number", { min: 1, max: 65535, placeholder: "1–65535" })}${field("proxy.username", "代理用户名", "text", { placeholder: "无认证时留空" })}${field("proxy.password", "代理密码", "password", { placeholder: "无认证时留空" })}</div><div id="proxy-parse-result" class="test-result proxy-parse-result" role="status"></div><div class="proxy-test-area"><button class="button primary" id="drawer-proxy-test" type="button">检测代理</button><span id="drawer-proxy-result" class="test-result" role="status"></span></div><div class="form-divider"></div><div class="info-banner">检测通过仅代表当前代理连接可用。每次打开窗口前都会重新检测已保存的代理，检测不通过则不会启动；认证信息只在本机使用。</div>`;
  const fingerprint = `${lifetimeNotice}<div class="form-intro"><div><div class="fingerprint-heading"><h3>指纹信息</h3>${state.creatingDraft ? '<button id="creation-randomize" class="button small" type="button">一键随机生成指纹配置</button>' : ""}</div><p>${state.creatingDraft ? "设置新窗口的浏览器环境信息" : "查看已保存的浏览器环境信息"}</p></div></div><div class="info-banner fingerprint-overview">${state.creatingDraft ? "为新窗口选择内核和指纹；提交后固定保存，日常打开不重新生成（启用“每次打开随机指纹”时除外）。" : state.draft?.created_locally ? "此处查看已创建窗口的固定指纹；每次打开是否随机由偏好设置决定。" : "指纹在比特配置后导入。本地副本保留导入时的指纹，此处仅供查看；重复同步不会覆盖已有副本。"}</div><div class="form-card"><h4 class="form-subtitle">浏览器与操作系统</h4><div class="form-grid">${fp(
    "ostype",
    "设备类型",
    "select",
    {
      options: [
        ["PC", "电脑"],
        ["Android", "Android"],
        ["IOS", "iOS"],
      ],
    },
  )}${fp("os", "操作系统", "select", {
    options: [
      ["Win32", "Windows"],
      ["MacIntel", "macOS"],
      ["Linux x86_64", "Linux"],
      ["Linux armv81", "Android"],
      ["iPhone", "iOS"],
    ],
  })}${fp("coreVersion", "浏览器内核", "select", { options: [["", "自动选择"], ...(state.creatingDraft ? state.creation.cores || [] : state.cores).map((core) => (typeof core === "string" ? [core, core] : [core.version || core.name, core.name || core.version]))], help: "必须与本机已安装的兼容浏览器内核匹配。" })}${fp("osVersion", "系统版本（兼容值）", "text", { hint: "仅保留原厂在线随机筛选值，本地不作为系统版本设置；请使用 User-Agent 与平台版本。" })}${fp("userAgent", "User-Agent", "textarea", { full: true, rows: 3, placeholder: "浏览器用户代理字符串", help: "应与设备类型、操作系统和内核版本一致。", hint: "相同系统与内核的 UA 可以相同，不代表全部指纹相同；UA 版本需匹配所选内核。" })}${fp("platformVersion", "平台版本", "text", { placeholder: "Client Hints 平台版本" })}${fp(
    "architecture",
    "CPU 架构",
    "select",
    {
      options: [
        ["x86", "x86"],
        ["arm", "ARM"],
        ["x86_64", "x86_64"],
      ],
    },
  )}${fp("hardwareConcurrency", "CPU 核心数", "number", { min: 1, max: 256 })}${fp("deviceMemory", "设备内存 (GB)", "number", { min: 0.25, max: 1024, step: "0.25" })}</div></div><div class="form-card"><h4 class="form-subtitle">语言与时区</h4><div class="form-grid">${fp("languages", "浏览器语言", "text", { placeholder: "zh-CN,zh", help: "多个语言以逗号分隔。" })}${fp("isIpCreateLanguage", "语言匹配 IP", "checkbox", { text: "根据代理 IP 自动匹配" })}${fp("displayLanguages", "界面语言", "text", { placeholder: "zh-CN" })}${fp("isIpCreateDisplayLanguage", "界面语言匹配 IP", "checkbox", { text: "根据代理 IP 自动匹配" })}${fp("timeZone", "时区", "text", { placeholder: "例如 Asia/Shanghai" })}${fp("isIpCreateTimeZone", "时区匹配 IP", "checkbox", { text: "根据代理 IP 自动匹配" })}</div></div><div class="form-card"><h4 class="form-subtitle">屏幕与窗口</h4><div class="form-grid">${fp(
    "resolutionType",
    "分辨率模式",
    "select",
    {
      options: [
        ["0", "使用系统分辨率"],
        ["1", "自定义分辨率"],
        ["2", "创建时随机固定"],
      ],
    },
  )}${fp("resolution", "屏幕分辨率", "text", { placeholder: "1920x1080", help: "自定义模式时使用，格式为宽x高。" })}${fp("openWidth", "窗口宽度", "number", { min: 320, max: 16384 })}${fp("openHeight", "窗口高度", "number", { min: 240, max: 16384 })}${fp(
    "colorDepth",
    "颜色深度",
    "select",
    {
      valueType: "number",
      options: [
        [24, "24 bit"],
        [30, "30 bit"],
        [32, "32 bit"],
        [48, "48 bit"],
      ],
    },
  )}${fp("devicePixelRatio", "设备像素比", "number", { min: 0.1, max: 10, step: "0.1", hint: "系统分辨率模式使用系统像素比；此处保留手动值，切回自定义或创建时随机模式后生效。" })}${fp("windowSizeLimit", "窗口尺寸限制", "checkbox", { text: "限制窗口尺寸", help: "限制窗口不超出配置的屏幕范围。" })}</div></div><div class="form-card"><h4 class="form-subtitle">字体与图形渲染</h4><div class="form-grid">${fp(
    "fontType",
    "字体模式",
    "select",
    {
      options: [
        ["0", "系统字体"],
        ["1", "自定义字体"],
        ["2", "随机选用本机字体"],
      ],
      help: "自定义仅支持本机已安装字体；匹配模式从本机字体中选择。原内核的额外跨系统字体文件加载存在兼容限制，未安装字体会明确报错。",
    },
  )}${fp("font", "字体列表", "textarea", { placeholder: "多个字体使用逗号分隔", help: "自定义字体模式下使用。" })}${fp("canvas", "Canvas", "select", { options: noiseOptions })}${fp("canvasValue", "Canvas 噪声值", "number", { valueType: "nullableNumber", step: "any", placeholder: "自动生成或自定义" })}${fp("webGL", "WebGL 图像", "select", { options: noiseOptions })}${fp("webGLValue", "WebGL 噪声值", "number", { valueType: "nullableNumber", step: "any", placeholder: "自动生成或自定义" })}${fp(
    "webGLMeta",
    "WebGL 元数据",
    "select",
    {
      options: [
        ["0", "自定义"],
        ["1", "真实"],
      ],
      help: "设置向网页报告的 GPU 厂商及渲染器。",
    },
  )}${fp("webgpu", "WebGPU 配置", "textarea", { valueType: "jsonobject", rows: 3, placeholder: "留空使用原生信息", help: "可选的完整 JSON 对象；结构需由有效模板或内核支持。" })}${fp("webGLManufacturer", "WebGL 厂商", "text", { placeholder: "GPU 厂商信息" })}${fp("webGLRender", "WebGL 渲染器", "text", { placeholder: "GPU 渲染器信息" })}${fp("clientRectNoiseEnabled", "Client Rects", "checkbox", { text: "启用矩形测量噪声", help: "为元素几何测量提供稳定的环境噪声。" })}${fp("clientRectNoiseValue", "Client Rects 噪声值", "number", { valueType: "nullableNumber", step: "any", placeholder: "自动生成或自定义" })}</div></div><div class="form-card"><h4 class="form-subtitle">音频、媒体与插件</h4><div class="form-grid">${fp("audioContext", "AudioContext", "select", { options: noiseOptions })}${fp("audioContextValue", "音频噪声值", "number", { valueType: "nullableNumber", step: "any", placeholder: "自动生成或自定义" })}${fp(
    "mediaDevice",
    "媒体设备",
    "select",
    {
      options: [
        ["0", "自定义覆盖"],
        ["1", "真实"],
      ],
      help: "覆盖模式需提供有效的媒体设备 JSON。",
    },
  )}${fp("mediaDeviceValue", "媒体设备 JSON", "textarea", { valueType: "jsontext", rows: 3, placeholder: "有效模板中的 JSON 文本", help: "覆盖模式为 0 时使用，保留完整模板结构。" })}${fp(
    "speechVoices",
    "语音列表",
    "select",
    {
      options: [
        ["0", "自定义覆盖"],
        ["1", "真实"],
      ],
    },
  )}${fp("speechVoicesValue", "语音列表 JSON", "textarea", { valueType: "jsontext", rows: 3, placeholder: "有效模板中的 JSON 文本" })}${fp("enablePlugins", "浏览器插件", "checkbox", { text: "启用插件信息" })}${fp("plugins", "插件列表 JSON", "textarea", { valueType: "jsonarray", rows: 3, placeholder: "JSON 数组", help: "插件记录数组，保留 name、filename、description、mimeType、mimeDescription、suffixes 等模板字段。" })}</div></div><div class="form-card"><h4 class="form-subtitle">隐私与地理位置</h4><div class="form-grid">${fp(
    "doNotTrack",
    "Do Not Track",
    "select",
    {
      options: [
        ["0", "不发送"],
        ["1", "启用"],
      ],
    },
  )}${fp("webRTC", "WebRTC", "select", {
    options: [
      ["2", "禁用"],
      ["3", "禁止非代理 UDP"],
      ["1", "真实"],
      ["0", "替换"],
    ],
    help: "禁止非代理 UDP 可减少本机地址泄漏风险。",
  })}${fp("position", "位置访问", "select", {
    options: [
      ["0", "询问"],
      ["1", "允许"],
      ["2", "禁止"],
    ],
  })}${fp("isIpCreatePosition", "位置匹配 IP", "checkbox", { text: "根据代理 IP 自动匹配" })}${fp("lat", "纬度", "number", { min: -90, max: 90, step: "any" })}${fp("lng", "经度", "number", { min: -180, max: 180, step: "any" })}${fp("defaultAccuracy", "位置精度 (米)", "number", { min: 1, max: 100000 })}</div></div><div class="form-card"><h4 class="form-subtitle">安全与设备信息</h4><div class="form-grid">${fp("disableSslCipherSuitesFlag", "SSL 密码套件", "checkbox", { text: "禁用指定密码套件", help: "调整 TLS 特征；错误配置可能导致网站连接失败。" })}${fp("disableSslCipherSuites", "禁用套件列表", "text", { placeholder: "多个套件使用逗号分隔" })}${fp(
    "portScanProtect",
    "端口扫描保护",
    "select",
    {
      options: [
        ["0", "启用"],
        ["1", "关闭"],
      ],
    },
  )}${fp("portWhiteList", "端口白名单", "text", { placeholder: "例如 80,443", help: "允许网页访问的本机端口。" })}${fp("deviceInfoEnabled", "设备信息", "checkbox", { text: "使用自定义设备标识" })}${fp("computerName", "计算机名称", "text", { placeholder: "自定义计算机名称" })}${fp("macAddr", "MAC 地址", "text", { placeholder: "00:00:00:00:00:00" })}${fp("launchArgs", "自定义启动参数", "textarea", { full: true, rows: 3, placeholder: "多个参数使用逗号分隔", help: "直接交给本地启动服务检查；受保护参数可能被拒绝。" })}</div></div><div class="form-card"><h4 class="form-subtitle">高级环境参数</h4><div class="form-grid">${fp("coreProduct", "内核类型", "select", { options: [["chrome", "Chromium / Chrome"]], help: "本地启动仅支持兼容的 Chromium 内核。" })}${fp("version", "浏览器版本（兼容值）", "text", { hint: "仅保留原厂在线随机筛选值，本地不使用；实际版本以所选内核和 User-Agent 为准。" })}${fp(
    "bitness",
    "架构位数",
    "select",
    {
      valueType: "number",
      options: [
        [32, "32 bit"],
        [64, "64 bit"],
      ],
    },
  )}${fp("iswow64", "WOW64", "checkbox", { text: "32 位应用运行在 64 位系统" })}${fp("uamodel", "设备型号", "text", { placeholder: "桌面设备通常留空" })}${fp("navigatorVendor", "浏览器厂商", "text", { placeholder: "Google Inc." })}${fp("timeZoneOffset", "时区偏移兼容值", "number", { hint: "只读兼容值；实际时区偏移由上方 IANA 时区和日期决定。" })}${fp("precisionData", "手动位置精度 (米)", "number", { min: 0, step: "any", help: "手动指定经纬度时使用。" })}${fp("hostIP", "WebRTC 替换地址", "text", { placeholder: "WebRTC 选择“替换”时使用" })}${fp("webglparameterscode", "WebGL 参数代码", "text", { placeholder: "有效模板中的参数代码", help: "需与 GPU 厂商、渲染器和完整参数匹配；不自动推断。" })}${fp("modelName", "设备型号名称", "text", { placeholder: "留空沿用模板默认值" })}${fp("manufacturerName", "设备制造商", "text", { placeholder: "留空沿用模板默认值" })}${fp("totalDiskSpace", "磁盘配额 (KiB)", "number", { min: 0, help: "空或 0 使用内核默认值。" })}${fp("ignoreHttpsErrors", "HTTPS 证书", "checkbox", { text: "允许忽略证书错误", help: "启用后可能接受不可信或过期的证书。" })}</div></div>`;
  const launchOptions = state.creatingDraft || state.draft?.created_locally ? `<div class="form-divider"></div><h4 class="form-subtitle">启动与清理</h4><div class="form-grid">${field("created_options.workbench", "打开时显示IP信息页", "select", {options:[["localserver","显示"],["disable","不显示"]]})}${field("created_options.dynamic_proxy_url", "动态代理提取链接", "text", {full:true,help:"可选。每次打开先提取1条代理，再经过正常转发和10秒检测。支持单条文本或JSON；失败不回退直连。"})}${field("created_options.dynamic_proxy_type", "提取代理协议", "select", {options:[["socks5","SOCKS5"],["http","HTTP"],["https","HTTPS"],["ssh","SSH"]]})}${[
    ["clear_cache", "启动前清理缓存", "只清理此窗口的受管缓存。"],
    ["clear_cache_without_extensions", "清理时保留扩展缓存", "配合清理缓存使用。"],
    ["clear_cookies", "启动前清理 Cookie", "会清除此窗口的登录Cookie，已登录网站可能需要重新登录。"],
    ["clear_history", "启动前清理历史", "清除此窗口的历史与访问索引。"],
    ["random_each_open", "每次打开随机指纹", "仅本地新建窗口支持；开启会改变环境，网站可能要求重新验证。"],
    ["stop_ip_change", "出口 IP 改变时停止打开", "与上次成功打开的出口比较。"],
    ["stop_country_change", "出口国家改变时停止打开", "无法核实国家时也停止打开。"],
    ["enable_background_mode", "允许浏览器后台运行", "关闭最后一个标签后仍可能由浏览器扩展保持进程。"],
  ].map(([key,label,hint])=>field(`created_options.${key}`,label,"checkbox",{text:"启用",help:hint})).join("")}${field("created_options.image_limit_kb", "禁止加载图片的大小下限（KiB）", "number", {min:0,max:102400,help:"配合禁止加载图片；0表示所有图片，大于0交由原生内核按大小限制。"})}</div>` : "";
  const preferences = `<div class="form-intro"><div><h3>偏好设置</h3><p>按需调整此窗口的浏览器行为，实际效果取决于内核支持</p></div></div><div class="form-grid">${preferenceDefinitions.map(([key, label, hint]) => field(`preferences.${key}`, label, "checkbox", { text: "启用", help: hint })).join("")}</div>${launchOptions}`;
  const cookies = `<div class="form-intro"><div><h3>Cookie 设置</h3><p>编辑或导入此窗口的 Cookie 文本</p></div></div><div class="cookie-toolbar"><span>支持格式以本地服务校验结果为准</span><button id="import-cookie" type="button" class="button small">${svg("import")}从文本文件导入</button></div>${field("cookie_text", "Cookie 内容", "textarea", { full: true, class: "cookie-editor", rows: 17, placeholder: "在此粘贴 Cookie 文本", help: "Cookie 可能包含登录状态，内容仅保留在本机。" })}<div class="info-banner" style="margin-top:20px">保存后由本地服务校验并应用 Cookie。请只导入你有权使用的登录信息。</div><input id="cookie-file-input" type="file" accept=".txt,.json,.cookies" hidden>`;
  $("#profile-form").innerHTML = Object.entries({
    basic,
    proxy,
    fingerprint,
    preferences,
    cookies,
  })
    .map(
      ([key, content]) =>
        `<section class="form-section ${state.section === key ? "active" : ""}" data-form-section="${key}">${content}</section>`,
    )
    .join("");
  updateFingerprintReadOnly();
}

function openDrawer(profile, section = "basic", focusField = null, creating = false) {
  if (!profile || isDeletePending(profile) || state.deletedIds.has(String(profile.id)) || state.operationActions.get(String(profile.id)) === "delete" || !$("#profile-drawer").hidden) return;
  state.creatingDraft = creating;
  state.draft = mergedProfile(profile);
  state.drawerSession++;
  state.dirty = false;
  state.section = section;
  state.saving = false;
  state.proxyRevision++;
  state.proxyParseRequest++;
  state.proxyParsePromise = null;
  state.proxyTestQueued = null;
  $("#drawer-title").textContent = creating ? "创建窗口" : "编辑窗口";
  showDrawerError("");
  buildProfileForm();
  setDrawerSection(section);
  $("#drawer-backdrop").hidden = false;
  $("#profile-drawer").hidden = false;
  $(".app-shell").inert = true;
  document.body.style.overflow = "hidden";
  setTimeout(() => {
    const focus =
      focusField
        ? $(`[data-field="${focusField}"]`)
        : section === "basic"
        ? $("#field-name")
        : $(".form-section.active input,.form-section.active select");
    focus?.focus();
    focus?.scrollIntoView({ block: "nearest" });
  }, 30);
}
function setDrawerSection(section) {
  state.section = section;
  $$("[data-section]").forEach((button) =>
    button.classList.toggle("active", button.dataset.section === section),
  );
  $$("[data-form-section]").forEach((el) =>
    el.classList.toggle("active", el.dataset.formSection === section),
  );
  $("#drawer-scroll").scrollTop = 0;
}
async function closeDrawer() {
  if (state.saving) return;
  if (
    state.dirty &&
    !(await confirmAction(
      "放弃未保存的修改",
      "当前窗口配置尚未保存，确认关闭吗？",
      "放弃修改",
    ))
  )
    return;
  $("#profile-drawer").hidden = true;
  $("#drawer-backdrop").hidden = true;
  $(".app-shell").inert = false;
  document.body.style.overflow = "";
  state.draft = null;
  state.creatingDraft = false;
  state.drawerSession++;
  state.dirty = false;
  state.proxyParseRequest++;
  state.proxyParsePromise = null;
  state.proxyTestQueued = null;
  $("#create-button").focus();
}
function readField(control) {
  if (!state.draft || isDeletePending(state.draft) || isDeletePending(profileById(state.draft.id)) || control.disabled) return;
  let value;
  if (control.dataset.type === "boolean") value = control.checked;
  else if (
    control.dataset.type === "number" ||
    control.dataset.type === "nullableNumber"
  )
    value =
      control.value.trim() === ""
        ? control.dataset.type === "nullableNumber"
          ? null
          : ""
        : Number(control.value);
  else if (control.dataset.type === "list") value = splitList(control.value);
  else if (control.dataset.type === "lines")
    value = control.value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
  else value = control.value;
  const previous = getPath(state.draft, control.dataset.field);
  if (Array.isArray(previous) && control.dataset.type === "string")
    value = splitList(value);
  setPath(state.draft, control.dataset.field, value);
  if (control.dataset.field.startsWith("fingerprint.") && previous !== value)
    state.creation.fingerprintRevision++;
  if (state.creatingDraft && previous !== value && ["fingerprint.coreVersion","fingerprint.os","fingerprint.ostype"].includes(control.dataset.field)) {
    const fp = state.draft.fingerprint;
    const deviceChanged = control.dataset.field === "fingerprint.ostype";
    if (deviceChanged) {
      const mobile = fp.ostype !== "PC";
      fp.openWidth = mobile ? 500 : 1280;
      fp.openHeight = mobile ? 950 : 720;
      fp.devicePixelRatio = fp.ostype === "Android" ? 2 : fp.ostype === "IOS" ? 3 : 1;
      fp.resolutionType = mobile ? "1" : "0";
      const resolutions = state.creation.resolutions?.[fp.ostype] || [];
      fp.resolution = mobile ? resolutions[Math.floor(Math.random() * resolutions.length)] || "" : "1920x1080";
      fp.osVersion = "";
    }
    if (fp.ostype === "Android") { fp.os = "Linux armv81"; fp.platformVersion = "14"; }
    else if (fp.ostype === "IOS") { fp.os = "iPhone"; fp.platformVersion = "18.0"; }
    else if (control.dataset.field === "fingerprint.ostype") { fp.os = "Win32"; fp.platformVersion = "10.0.0"; }
    else if (control.dataset.field === "fingerprint.os") fp.platformVersion = fp.os === "MacIntel" ? "10.15.7" : fp.os === "Win32" ? "10.0.0" : "";
    const major = fp.coreVersion || "148";
    const platform = fp.os === "MacIntel" ? "Macintosh; Intel Mac OS X 10_15_7" : String(fp.os).startsWith("Linux") ? "X11; Linux x86_64" : "Windows NT 10.0; Win64; x64";
    fp.userAgent = fp.ostype === "Android" ? `Mozilla/5.0 (Linux; Android ${fp.platformVersion}; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Mobile Safari/537.36`
      : fp.ostype === "IOS" ? `Mozilla/5.0 (iPhone; CPU iPhone OS ${String(fp.platformVersion).replaceAll(".","_")} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/${major}.0.0.0 Mobile/15E148 Safari/604.1`
      : `Mozilla/5.0 (${platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;
    const presets = (state.creation.presets || []).filter(p => p.ostype === fp.ostype && p.os === fp.os);
    const matched = presets.find(p => p.core === major) || presets[0];
    if (matched) {
      Object.assign(fp, copy(matched.values));
      const version = state.creation.builds?.[major] || `${major}.0.0.0`;
      fp.userAgent = fp.userAgent.replace(/(Chrome\/|CriOS\/)[0-9.]+/, `$1${version}`);
      for (const key of ["architecture","uamodel","webGLManufacturer","webGLRender","webgpu"]) {
        const control = $("#field-fingerprint-" + key);
        if (control) control.value = key === "webgpu" && fp[key] ? JSON.stringify(fp[key]) : fp[key] || "";
      }
    }
    const ua = $("#field-fingerprint-userAgent"); if (ua) ua.value = fp.userAgent;
    const os = $("#field-fingerprint-os"); if (os) os.value = fp.os;
    const version = $("#field-fingerprint-platformVersion"); if (version) version.value = fp.platformVersion;
    if (deviceChanged) {
      for (const key of ["openWidth","openHeight","devicePixelRatio","resolutionType","resolution","osVersion"]) {
        const target = $("#field-fingerprint-" + key);
        if (target) target.value = fp[key];
      }
    }
  }
  if (state.creatingDraft && previous !== value && ["fingerprint.resolutionType", "fingerprint.ostype"].includes(control.dataset.field))
    updateFingerprintReadOnly();
  if (control.dataset.field === "cookie_text" && previous !== value) {
    state.cookieReadRequest++;
    const input = $("#cookie-file-input");
    if (input) input.value = "";
  }
  if (control.dataset.field.startsWith("proxy.") && previous !== value) {
    state.proxyRevision++;
    state.proxyTestQueued = null;
    const result = $("#drawer-proxy-result");
    if (result?.textContent) {
      result.className = "test-result";
      result.textContent = "代理参数已修改，请重新检测。";
    }
    const parsed = $("#proxy-parse-result");
    if (parsed) parsed.textContent = "";
  }
  state.dirty = true;
}
function hasProxyAddress(value) {
  return /:\/\/|\||:\d+(?::|$)/.test(String(value).trim().replaceAll("：", ":"));
}
function parseProxyText(text) {
  const draft = state.draft;
  if (!draft) return Promise.resolve(false);
  const revision = ++state.proxyRevision;
  state.proxyTestQueued = null;
  const request = ++state.proxyParseRequest;
  const resultElement = $("#proxy-parse-result");
  resultElement.className = "test-result proxy-parse-result";
  resultElement.textContent = "正在识别代理…";
  const testResult = $("#drawer-proxy-result");
  testResult.className = "test-result";
  testResult.textContent = "识别完成后将自动检测代理。";
  const promise = (async () => {
    try {
      const result = await api("proxy_parse", {
        text,
        default_type: draft.proxy?.type || "http",
      });
      if (state.draft !== draft || state.proxyParseRequest !== request) return false;
      if (state.proxyRevision !== revision) {
        resultElement.textContent = "代理参数已修改，请重新粘贴完整代理。";
        return false;
      }
      if (!result?.proxy || typeof result.proxy !== "object") throw new Error();
      for (const key of ["type", "host", "port", "username", "password"]) {
        const control = $(`[data-field="proxy.${key}"]`);
        if (!control) continue;
        control.value = result.proxy[key] ?? "";
        readField(control);
      }
      resultElement.className = "test-result proxy-parse-result success";
      resultElement.textContent = result.ignored_metadata
        ? "代理已自动分填，尾部附加信息已忽略。正在自动检测。"
        : "代理已自动分填，正在自动检测。";
      return true;
    } catch {
      if (state.draft === draft && state.proxyParseRequest === request) {
        resultElement.className = "test-result proxy-parse-result failure";
        resultElement.textContent = "代理识别失败，请检查格式，或分开填写主机、端口和认证信息。";
        testResult.textContent = "";
      }
      return false;
    } finally {
      if (state.proxyParseRequest === request) state.proxyParsePromise = null;
    }
  })();
  state.proxyParsePromise = promise;
  promise.then((parsed) => {
    if (parsed && state.draft === draft && state.proxyParseRequest === request) {
      queueDrawerProxyTest();
    }
  });
  return promise;
}
async function ensureProxyParsed() {
  if (state.proxyParsePromise && !(await state.proxyParsePromise)) return false;
  const host = $("#field-proxy-host")?.value || "";
  return !hasProxyAddress(host) || parseProxyText(host);
}
function collectDraft() {
  $$("[data-field]", $("#profile-form")).forEach((control) => {
    const wasDirty = state.dirty;
    readField(control);
    state.dirty = wasDirty;
  });
  return copy(state.draft);
}
function validateDraft(profile) {
  if (!profile.name?.trim())
    return { section: "basic", field: "name", message: "请输入窗口名称。" };
  if (profile.proxy?.type !== "noproxy") {
    if (!profile.proxy?.host?.trim())
      return {
        section: "proxy",
        field: "proxy.host",
        message: "请输入代理主机。",
      };
    if (
      !Number.isInteger(Number(profile.proxy.port)) ||
      Number(profile.proxy.port) < 1 ||
      Number(profile.proxy.port) > 65535
    )
      return {
        section: "proxy",
        field: "proxy.port",
        message: "代理端口须为 1–65535 的整数。",
      };
  }
  for (const control of $$('input[type="number"]', $("#profile-form"))) {
    if (control.disabled) continue;
    if ((control.value !== "" || control.validity?.badInput) && !control.checkValidity())
      return {
        section: control.closest("[data-form-section]").dataset.formSection,
        field: control.dataset.field,
        message: `请检查“${control.closest(".field").querySelector(".field-label").textContent.replace(/[?*]/g, "").trim()}”的数值范围。`,
      };
  }
  for (const control of $$('[data-type^="json"]', $("#profile-form"))) {
    if (control.disabled) continue;
    if (!control.value.trim()) continue;
    try {
      const parsed = JSON.parse(control.value);
      if (
        control.dataset.type === "jsonobject" &&
        (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      )
        throw new Error();
      if (control.dataset.type === "jsonarray" && !Array.isArray(parsed))
        throw new Error();
    } catch {
      return {
        section: "fingerprint",
        field: control.dataset.field,
        message: `请为“${control.closest(".field").querySelector(".field-label").textContent.replace(/[?*]/g, "").trim()}”填写有效的 ${control.dataset.type === "jsonarray" ? "JSON 数组" : control.dataset.type === "jsonobject" ? "JSON 对象" : "JSON 文本"}。`,
      };
    }
  }
  return null;
}
function prepareDraft(profile) {
  $$('[data-type="jsonobject"]:not(:disabled)', $("#profile-form")).forEach((control) =>
    setPath(
      profile,
      control.dataset.field,
      control.value.trim() ? JSON.parse(control.value) : null,
    ),
  );
  $$('[data-type="jsontext"]:not(:disabled)', $("#profile-form")).forEach((control) =>
    setPath(profile, control.dataset.field, control.value.trim() || null),
  );
  return profile;
}
async function saveProfile() {
  if (state.saving || state.preparingSave || !state.draft || state.operationActions.get(String(state.draft.id)) === "delete") return;
  if (isDeletePending(state.draft) || isDeletePending(profileById(state.draft.id))) {
    showDrawerError("删除未完成，请关闭编辑并重新执行删除。");
    return;
  }
  state.preparingSave = true;
  try {
    if (!(await ensureProxyParsed())) return;
  } finally {
    state.preparingSave = false;
  }
  if (!state.draft || isDeletePending(state.draft) || isDeletePending(profileById(state.draft.id))) return;
  const profile = collectDraft();
  const problem = validateDraft(profile);
  if (problem) {
    setDrawerSection(problem.section);
    showDrawerError(problem.message);
    $(`[data-field="${problem.field}"]`)?.focus();
    return;
  }
  prepareDraft(profile);
  profile.name = profile.name.trim();
  profile.core_version =
    profile.fingerprint.coreVersion || profile.core_version;
  profile.os = profile.fingerprint.os;
  if (state.creatingDraft) return submitCreation(profile);
  state.saving = true;
  setDrawerBusy(true, "正在保存窗口…");
  showDrawerError("");
  try {
    await api("save", { profile });
  } catch (error) {
    showDrawerError(error.message);
    state.saving = false;
    setDrawerBusy(false);
    return;
  }
  state.dirty = false;
  state.saving = false;
  setDrawerBusy(false);
  await closeDrawer();
  try {
    await refreshProfiles();
    toast("窗口配置已保存。", "success");
  } catch (error) {
    showServiceError(`窗口配置已保存，但列表刷新失败：${error.message}`);
    toast("配置已保存，请刷新窗口列表。", "error");
  }
}
function setDrawerBusy(busy, label) {
  $("#save-profile").disabled = busy;
  $("#save-profile").classList.toggle("is-loading", busy);
  $("#save-profile").textContent = busy ? label || "处理中…" : "确定";
  $("#cancel-drawer").disabled = busy;
  $("#close-drawer").disabled = busy;
  $("#profile-form").inert = busy;
  $("#drawer-nav").inert = busy;
}
function testMessage(result) {
  if (!result || typeof result !== "object")
    return { success: false, message: "检测失败 · 本地服务未返回有效的代理检测结果。" };
  return {
    success: result.success === true,
    message: [
      result.success === true ? "检测成功" : "检测失败",
      result.message || (result.success === true ? "连接成功" : "代理连接失败"),
      result.egress_ip ? `出口 IP：${result.egress_ip}` : "",
    ]
      .filter(Boolean)
      .join(" · "),
  };
}
function drawerProxyTicketCurrent(ticket) {
  return state.draft === ticket.draft &&
    state.proxyRevision === ticket.revision &&
    state.proxyParseRequest === ticket.parseRequest &&
    !$("#profile-drawer").hidden && !state.saving;
}
function queueDrawerProxyTest() {
  if (!state.draft || $("#profile-drawer").hidden || state.saving) return;
  state.proxyTestQueued = {
    draft: state.draft,
    revision: state.proxyRevision,
    parseRequest: state.proxyParseRequest,
  };
  $("#drawer-proxy-test").disabled = true;
  if (state.proxyTestActive) {
    const result = $("#drawer-proxy-result");
    result.className = "test-result";
    result.textContent = "正在等待当前检测结束，随后检测最新代理…";
  }
  return drainDrawerProxyTests();
}
async function drainDrawerProxyTests() {
  if (state.proxyTestActive) return;
  state.proxyTestActive = true;
  try {
    while (state.proxyTestQueued) {
      const ticket = state.proxyTestQueued;
      state.proxyTestQueued = null;
      if (!drawerProxyTicketCurrent(ticket)) continue;
      if (!(await ensureProxyParsed()) || !drawerProxyTicketCurrent(ticket)) continue;
      await runProxyTest(null, $("#drawer-proxy-test"), $("#drawer-proxy-result"));
    }
  } finally {
    state.proxyTestActive = false;
    const button = $("#drawer-proxy-test");
    if (button) button.disabled = state.saving;
  }
}
function testProxy(id = null, button = null, resultElement = null) {
  return id ? runProxyTest(id, button, resultElement) : queueDrawerProxyTest();
}
async function runProxyTest(id = null, button = null, resultElement = null) {
  if (id && button?.disabled) return;
  if (button) button.disabled = true;
  const profile = id ? profileById(id) : collectDraft();
  if (!profile) {
    if (button) button.disabled = false;
    return;
  }
  const draft = state.draft;
  const revision = state.proxyRevision;
  const isCurrent = () => id || (state.draft === draft && state.proxyRevision === revision);
  const proxy = copy(profile.proxy || {});
  if (proxy.type !== "noproxy" && (!proxy.host || !proxy.port)) {
    const msg = "请先填写代理主机和端口。";
    if (resultElement) {
      resultElement.textContent = `检测失败 · ${msg}`;
      resultElement.className = "test-result failure";
    } else toast(msg, "error");
    if (button) button.disabled = false;
    return;
  }
  if (resultElement) {
    resultElement.textContent = "正在检测连接…";
    resultElement.className = resultElement.classList.contains("proxy-result")
      ? "proxy-result"
      : "test-result";
  }
  try {
    const result = testMessage(
      await api("proxy_test", { proxy, ...(id ? { id } : {}) }),
    );
    if (!isCurrent()) return;
    if (resultElement) {
      const base = resultElement.classList.contains("proxy-result")
        ? "proxy-result"
        : "test-result";
      resultElement.className = `${base} ${result.success ? "success" : "failure"}`;
      resultElement.textContent = result.message;
    } else toast(result.message, result.success ? "success" : "error");
  } catch (error) {
    if (!isCurrent()) return;
    if (resultElement) {
      resultElement.textContent = `检测失败 · ${error.message}`;
      resultElement.classList.add("failure");
    } else toast(error.message, "error");
  } finally {
    if (button) button.disabled = false;
  }
}

function forgetDeletedProfiles(ids) {
  const deleted = new Set(ids.map(String));
  for (const id of deleted) {
    state.deletedIds.add(id);
    state.selected.delete(id);
    state.recycleSelected.delete(id);
  }
  state.profiles = state.profiles.filter((profile) => !deleted.has(String(profile.id)));
  if (state.draft && deleted.has(String(state.draft.id))) {
    state.draft = null;
    state.dirty = false;
    state.drawerSession++;
    state.cookieReadRequest++;
    state.proxyRevision++;
    state.proxyParseRequest++;
    state.proxyParsePromise = null;
    state.proxyTestQueued = null;
    $("#profile-form").innerHTML = "";
    $("#profile-drawer").hidden = true;
    $("#drawer-backdrop").hidden = true;
    $(".app-shell").inert = false;
    document.body.style.overflow = "";
  }
  $("#row-menu").hidden = true;
  $("#row-menu").innerHTML = "";
  state.sync.previewRevision++;
  state.sync.loading = false;
  state.sync.previewId = null;
  state.sync.preview = [];
  state.sync.names.clear();
  state.sync.selected.clear();
  if (state.sync.status) state.sync.status = { ...state.sync.status, items: [] };
  $("#sync-result-list").innerHTML = "";
  invalidateSyncStatus();
  scheduleSyncStatus(0);
  renderSync();
}
async function deleteProfiles(ids, button = null, { selection = null, recycle = false } = {}) {
  if (state.deleteBusy || state.batchBusy || state.saving || state.preparingSave || state.loading) return;
  ids = [...new Set(ids.map(String))];
  if (!ids.length) return;
  const profiles = ids.map(profileById);
  if (profiles.some((profile, index) => !profile || isArchived(profile) !== recycle || state.operationIds.has(ids[index]) || state.deletedIds.has(ids[index]))) {
    toast("窗口或选择已变化，请刷新后重新选择。", "error");
    return;
  }
  const panel = state.panel;
  const batch = Boolean(selection);
  const label = button?.textContent;
  let submitted = false, invalidated = false, completed = 0, processed = 0;
  const failures = [];
  state.deleteBusy = true;
  if (batch) state.batchBusy = true;
  state.statusRevision++;
  ids.forEach((id) => { state.operationIds.add(id); state.operationActions.set(id, "delete"); });
  if (button) button.disabled = true;
  renderProfiles();
  renderRecycle();
  try {
    if (!(await confirmAction(
      batch ? "彻底删除所选窗口" : "彻底删除窗口",
      `${batch ? `已选 ${ids.length} 个窗口` : `“${profiles[0].name || "未命名窗口"}”`}将被彻底删除，无法恢复。程序会先正常关闭所选的本地浏览器窗口，再删除本程序中的配置、浏览器资料和可识别的恢复副本。未保存的修改也会丢失。共用内核、原比特来源、手动导出及外部备份不删除。原比特来源保留，日后同步仍可重新导入。确认继续？`,
      "彻底删除",
    ))) return;
    const selectionChanged = selection && (selection !== (recycle ? state.recycleSelected : state.selected) || selection.size !== ids.length || ids.some((id) => !selection.has(id)));
    if (state.panel !== panel || state.saving || state.preparingSave || selectionChanged || profiles.some((profile, index) => profileById(ids[index]) !== profile || isArchived(profile) !== recycle)) {
      toast("窗口或选择已变化，未执行删除，请重新确认。", "error");
      return;
    }
    submitted = true;
    if (button) button.textContent = "正在彻底删除…";
    for (let offset = 0; offset < ids.length; offset += 100) {
      const chunk = ids.slice(offset, offset + 100);
      const result = batch ? await api("batch", { action: "delete", ids: chunk }) : await api("delete", { id: chunk[0] });
      const results = batch ? (Array.isArray(result?.results) ? result.results : []) : [{ id: chunk[0], ok: true, data: result }];
      const deleted = [], retired = [];
      for (const id of chunk) {
        const matches = results.filter((item) => String(item?.id) === id);
        const item = matches.length === 1 ? matches[0] : null;
        if (item?.data?.deleted === true) retired.push(id);
        if (item?.ok === true && item.data?.deleted === true && item.data?.cleanup_complete === true) deleted.push(id);
        else failures.push(item?.error || (item?.data?.cleanup_complete === false ? "删除后的存储清理未完成，请重启程序继续清理。" : "本地服务未确认完整删除。"));
      }
      if (retired.length) { forgetDeletedProfiles(retired); invalidated = true; }
      completed += deleted.length;
      processed += chunk.length;
    }
    if (failures.length) toast(`删除结束：已彻底删除 ${completed} 个，失败或清理未完成 ${failures.length} 个。${[...new Set(failures)].slice(0, 3).join("；")}`, "error");
    else toast(`已彻底删除 ${completed} 个窗口，无法恢复。`, "success");
  } catch (error) {
    toast(`删除中断：已确认彻底删除 ${completed} 个，失败或清理未完成 ${failures.length} 个，另有 ${ids.length - processed} 个结果未确认。${error.message}`, "error");
  } finally {
    if (submitted) {
      try {
        await refreshProfiles();
        const absent = ids.filter((id) => !profileById(id) && !state.deletedIds.has(id));
        if (absent.length) { forgetDeletedProfiles(absent); invalidated = true; }
      }
      catch (error) { showServiceError(`删除结果已返回，但列表刷新失败：${error.message}`); }
      if (invalidated) {
        let previewRefresh = false;
        try {
          if (await refreshSyncAfterDelete()) { previewRefresh = true; await loadSyncPreview(); }
        }
        catch { showSyncError("来源预览刷新失败，请重新预览。"); }
        if (state.sync.error) showServiceError(previewRefresh ? "来源预览刷新失败，请重新预览。删除结果以上方提示为准；原比特来源仍可能再次导入。" : state.sync.error);
      }
    }
    state.deleteBusy = false;
    if (batch) state.batchBusy = false;
    ids.forEach((id) => { state.operationIds.delete(id); state.operationActions.delete(id); });
    if (button) { button.textContent = label; button.disabled = false; }
    renderProfiles();
    renderRecycle();
  }
}
async function performAction(action, id) {
  if (state.deleteBusy || state.operationIds.has(String(id)) || state.deletedIds.has(String(id))) return;
  const profile = profileById(id);
  if (!profile) return;
  if (action === "delete") return deleteProfiles([id], null, { recycle: isArchived(profile) });
  if (isDeletePending(profile) && action !== "close") {
    toast("删除未完成，请重新执行删除。", "error");
    return;
  }
  if (["edit", "proxy", "tags", "remark"].includes(action)) {
    openDrawer(
      profile,
      action === "proxy" ? "proxy" : "basic",
      action === "proxy" ? "proxy.host" : action === "edit" ? null : action,
    );
    return;
  }
  if (
    action === "archive" &&
    !(await confirmAction(
      "移至回收站",
      `将“${profile.name}”移至回收站？配置和浏览器资料会保留，可在回收站恢复。`,
      "移至回收站",
    ))
  )
    return;
  if (
    action === "close" &&
    state.settings.confirm_close !== false &&
    !(await confirmAction(
      "关闭浏览器",
      `确认关闭“${profile.name}”的浏览器窗口？`,
      "关闭窗口",
    ))
  )
    return;
  if (state.deleteBusy || state.operationIds.has(String(id)) || profileById(id) !== profile) return;
  state.operationIds.add(String(id));
  state.operationActions.set(String(id), action);
  state.statusRevision++;
  renderProfiles();
  try {
    await api(action, { id });
    await refreshProfiles();
    const messages = {
      open: "窗口已打开。",
      activate: "已激活浏览器窗口。",
      close: "窗口已关闭。",
      archive: "已移至回收站，可随时恢复。",
      restore: "窗口已恢复。",
    };
    if (messages[action]) toast(messages[action], "success");
  } catch (error) {
    toast(error.message, "error");
  } finally {
    state.operationIds.delete(String(id));
    state.operationActions.delete(String(id));
    renderProfiles();
  }
}
function openRowMenu(id, anchor) {
  const profile = profileById(id);
  if (!profile) return;
  const menu = $("#row-menu");
  const blocked = isDeletePending(profile) ? "disabled" : "";
  menu.innerHTML = `<button data-menu-action="edit" data-id="${esc(id)}" role="menuitem" ${blocked}>${svg("edit")}编辑窗口</button>${isRunning(profile) ? `<button data-menu-action="activate" data-id="${esc(id)}" role="menuitem" ${blocked}>${svg("windows")}激活窗口</button><button data-menu-action="close" data-id="${esc(id)}" role="menuitem">${svg("stop")}关闭窗口</button>` : ""}<div class="menu-separator"></div><button class="danger-text" data-menu-action="archive" data-id="${esc(id)}" role="menuitem" ${blocked}>${svg("trash")}移至回收站</button><button class="danger-text" data-menu-action="delete" data-id="${esc(id)}" role="menuitem">${svg("trash")}删除</button>`;
  menu.hidden = false;
  const rect = anchor.getBoundingClientRect();
  menu.style.left = `${Math.max(8, Math.min(rect.right - menu.offsetWidth, innerWidth - menu.offsetWidth - 12))}px`;
  menu.style.top = `${rect.bottom + menu.offsetHeight + 8 > innerHeight ? Math.max(8, rect.top - menu.offsetHeight - 5) : rect.bottom + 5}px`;
  menu.querySelector("button")?.focus();
}
async function batchAction(action, button, { recycle = false } = {}) {
  if (state.batchBusy || state.deleteBusy) return;
  if (action === "delete") {
    const selection = recycle ? state.recycleSelected : state.selected;
    return deleteProfiles(Array.from(selection), button, { selection, recycle });
  }
  const ids = Array.from(state.selected);
  if (!ids.length) return;
  if (action !== "close" && ids.some((id) => isDeletePending(profileById(id)))) {
    toast("所选窗口包含删除未完成的记录，请重新执行删除。", "error");
    return;
  }
  if (
    action === "archive" &&
    !(await confirmAction(
      "批量移至回收站",
      `将已选的 ${ids.length} 个窗口移至回收站？配置和浏览器资料会保留。`,
      "移至回收站",
    ))
  )
    return;
  if (
    action === "close" &&
    state.settings.confirm_close !== false &&
    !(await confirmAction(
      "批量关闭窗口",
      `确认关闭已选的 ${ids.length} 个浏览器窗口？`,
      "关闭窗口",
    ))
  )
    return;
  if (state.batchBusy || state.deleteBusy) return;
  button.disabled = true;
  const label = button.textContent;
  if (action === "open") button.textContent = "检测代理并打开…";
  state.batchBusy = true;
  state.statusRevision++;
  ids.forEach((id) => {
    state.operationIds.add(String(id));
    state.operationActions.set(String(id), action);
  });
  renderProfiles();
  let completed = 0;
  let processed = 0;
  const errors = [];
  try {
    for (let offset = 0; offset < ids.length; offset += 100) {
      const chunk = ids.slice(offset, offset + 100);
      const result = await api("batch", { action, ids: chunk });
      const failures = Array.isArray(result?.errors)
        ? result.errors
        : Array.isArray(result?.results)
          ? result.results.filter((item) => item.ok === false || item.success === false)
          : [];
      errors.push(...failures);
      completed += Number.isFinite(Number(result?.completed))
        ? Math.min(chunk.length, Math.max(0, Math.floor(Number(result.completed))))
        : Math.max(0, chunk.length - failures.length);
      processed += chunk.length;
    }
    if (errors.length)
      toast(
        `批量操作结束：成功 ${completed} 个，失败 ${errors.length} 个。${errors.map((item) => (typeof item === "string" ? item : item.error || item.message || "操作失败")).join("；")}`,
        "error",
      );
    else toast(`批量操作已完成：成功 ${completed} 个。`, "success");
  } catch (error) {
    toast(`批量操作中断：已确认成功 ${completed} 个，失败 ${errors.length} 个，另有 ${ids.length - processed} 个结果未确认。${error.message}`, "error");
  } finally {
    try {
      await refreshProfiles();
    } catch (error) {
      showServiceError(`批量操作结果已返回，但列表刷新失败：${error.message}`);
    }
    state.batchBusy = false;
    ids.forEach((id) => {
      state.operationIds.delete(String(id));
      state.operationActions.delete(String(id));
    });
    button.textContent = label;
    renderProfiles();
  }
}
async function exportProfiles(button) {
  button.disabled = true;
  try {
    if (
      !(await confirmAction(
        "导出窗口配置",
        "导出可能包含代理认证和登录信息，请将文件保存在你信任的本机位置。",
        "选择保存位置",
      ))
    )
      return;
    const result = await api("export_profiles", {
      ids: state.selected.size ? Array.from(state.selected) : [],
    });
    if (result?.cancelled) return;
    toast(
      result?.message || "窗口配置已导出。",
      result?.errors?.length ? "error" : "success",
    );
  } catch (error) {
    toast(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function openCreation(batch = false) {
  if (state.creation.opening || !$("#profile-drawer").hidden) return;
  state.creation.opening = true;
  try {
    const options = await api("creation_options");
    if (options.latest && ["running", "interrupted", "failed"].includes(options.latest.state)) {
      acceptCreationJob(options.latest);
      showCreationProgress();
      return;
    }
    const draft = mergedProfile(options.defaults);
    draft.creation = { count: batch ? 10 : 1, random_each: batch, proxy_lines: [] };
    state.creation.cores = options.cores;
    state.creation.presets = options.presets || [];
    state.creation.builds = options.builds || {};
    state.creation.resolutions = options.resolutions || {};
    state.creation.requestId = window.crypto.randomUUID().replaceAll("-", "");
    openDrawer(draft, "basic", null, true);
  } catch (error) { toast(error.message, "error"); }
  finally { state.creation.opening = false; }
}

async function randomizeCreation() {
  if (!state.creatingDraft || !state.draft || state.saving || state.preparingSave) return;
  collectDraft();
  const draft = state.draft, session = state.drawerSession;
  const fingerprint = copy(draft.fingerprint), revision = state.creation.fingerprintRevision;
  const current = () => draft === state.draft && session === state.drawerSession;
  showDrawerError("");
  state.saving = true; setDrawerBusy(true, "生成指纹…");
  try {
    const result = await api("creation_randomize", { fingerprint });
    if (!current()) return;
    if (revision !== state.creation.fingerprintRevision || JSON.stringify(draft.fingerprint) !== JSON.stringify(fingerprint)) {
      showDrawerError("指纹参数已修改，本次随机结果未应用；请确认当前参数后重新随机。");
      return;
    }
    if (!result?.fingerprint || typeof result.fingerprint !== "object" || Array.isArray(result.fingerprint))
      throw new Error("未取得有效的随机指纹，请重试。");
    draft.fingerprint = result.fingerprint;
    state.creation.fingerprintRevision++;
    state.dirty = true;
    $$('[data-field^="fingerprint."]', $("#profile-form")).forEach((control) => {
      const value = getPath(draft, control.dataset.field);
      if (control.dataset.type === "boolean") control.checked = value === true || value === 1 || value === "1" || value === "true";
      else control.value = fieldText(value, control.dataset.type);
    });
    updateFingerprintReadOnly();
    toast("随机指纹已更新，可继续调整后创建。", "success");
  } catch (error) { if (current()) showDrawerError(error.message); }
  finally { if (current()) { state.saving = false; setDrawerBusy(false); } }
}

async function submitCreation(profile) {
  const options = profile.creation || {};
  const count = Number(options.count);
  if (!Number.isInteger(count) || count < 1 || count > 1000) return showDrawerError("创建数量须为1至1000的整数。");
  delete profile.creation;
  state.saving = true; setDrawerBusy(true, "提交创建任务…");
  state.creation.revision++;
  try {
    const job = await api("create_windows", { request_id: state.creation.requestId,
      profile, count, random_each: options.random_each === true, proxy_lines: options.proxy_lines || [] });
    acceptCreationJob(job);
    state.dirty = false;
    state.saving = false; setDrawerBusy(false);
    await closeDrawer();
    showCreationProgress();
    if (job.state !== "running") await refreshCreatedProfiles();
  } catch (error) {
    showDrawerError(error.message + " 若提交结果未确认，请保持表单原样重试；相同请求不会重复创建。");
  } finally { state.saving = false; setDrawerBusy(false); }
}

async function refreshCreatedProfiles() {
  const revision = state.creation.revision;
  try { await refreshProfiles(); }
  catch {
    if (revision !== state.creation.revision) return;
    $("#creation-error").textContent = "创建进度已更新，但窗口列表刷新失败，请刷新窗口列表。";
    $("#creation-error").hidden = false;
  }
}

function acceptCreationJob(job) {
  state.creation.revision++;
  state.creation.job = job;
  $("#creation-progress-button").hidden = !job;
  clearTimeout(state.creation.timer);
  if (!job) {
    $("#creation-summary").textContent = "没有待处理的创建任务。";
    $("#creation-progress").max = 1;
    $("#creation-progress").value = 0;
    $("#creation-results").innerHTML = "";
    $("#creation-cancel").hidden = true;
    $("#creation-resume").hidden = true;
    return;
  }
  const labels = { running: "创建中", interrupted: "已中断，可继续", completed: "创建完成", failed: "部分失败，可重试", cancelled: "已取消剩余项" };
  $("#creation-summary").textContent = `${labels[job.state] || job.state} · 成功 ${job.completed} / ${job.total}，失败 ${job.failed}`;
  $("#creation-progress").max = Math.max(1, job.total);
  $("#creation-progress").value = job.completed + job.failed;
  $("#creation-results").innerHTML = (job.items || []).map((item) => `<p>${esc(item.index)} · ${esc(item.message)}</p>`).join("");
  $("#creation-cancel").hidden = !["running", "interrupted", "failed"].includes(job.state);
  $("#creation-cancel").disabled = job.cancel_requested;
  $("#creation-resume").hidden = !["interrupted", "failed"].includes(job.state);
  clearTimeout(state.creation.timer);
  if (job.state === "running") state.creation.timer = setTimeout(() => pollCreation(), 1000);
}

function showCreationProgress() {
  if (!$("#creation-dialog").open) $("#creation-dialog").showModal();
  pollCreation(true);
}

async function pollCreation(manual = false) {
  const creation = state.creation;
  if (!creation.job || creation.reading) return;
  creation.reading = true;
  let failed = false;
  const jobId = creation.job.job_id, revision = creation.revision;
  try {
    const job = await api("creation_status", { job_id: jobId, missing_ok: true });
    if (jobId !== creation.job?.job_id || revision !== creation.revision) return;
    const finished = creation.job.state === "running" && job?.state !== "running";
    $("#creation-error").hidden = true;
    acceptCreationJob(job);
    if (finished) await refreshCreatedProfiles();
  } catch (error) {
    if (jobId !== creation.job?.job_id || revision !== creation.revision) return;
    failed = true;
    $("#creation-error").textContent = error.message + "，请刷新进度。";
    $("#creation-error").hidden = false;
  } finally {
    creation.reading = false;
    if (!failed && creation.job?.state === "running" && !creation.mutating) {
      clearTimeout(creation.timer);
      creation.timer = setTimeout(() => pollCreation(), 1000);
    }
  }
}

async function mutateCreation(action) {
  const job = state.creation.job;
  if (!job || state.creation.mutating) return;
  state.creation.mutating = true;
  state.creation.revision++;
  clearTimeout(state.creation.timer);
  try {
    const updated = await api(action, { job_id: job.job_id });
    acceptCreationJob(updated);
    if (updated.state !== "running") await refreshCreatedProfiles();
  }
  catch (error) { $("#creation-error").textContent = error.message; $("#creation-error").hidden = false; }
  finally { state.creation.mutating = false; }
}

function bindEvents() {
  $("#new-window-button").onclick = () => openCreation(false);
  $("#batch-create-button").onclick = () => openCreation(true);
  $("#creation-progress-button").onclick = showCreationProgress;
  $("#creation-close").onclick = () => $("#creation-dialog").close();
  $("#creation-cancel").onclick = () => mutateCreation("cancel_creation");
  $("#creation-resume").onclick = () => mutateCreation("resume_creation");
  $("#creation-refresh").onclick = () => pollCreation(true);
  $$(".nav-item").forEach((button) =>
    button.addEventListener("click", () => navigate(button.dataset.panel)),
  );
  $("#recycle-nav").onclick = () => navigate("recycle");
  $("#refresh-button").onclick = async () => {
    if (state.groupsSaving || state.settingsSaving) return;
    const hasDraft =
      state.panel === "groups" &&
      JSON.stringify(state.groupDraft) !== JSON.stringify(state.groupOriginal);
    if (
      (hasDraft || (state.panel === "settings" && state.settingsDirty)) &&
      !(await confirmAction(
        "刷新本地数据",
        "当前修改尚未保存，刷新会重新读取本地数据。确认继续吗？",
        "刷新",
      ))
    )
      return;
    await bootstrap();
  };
  $("#create-button").onclick = () => openSyncDialog();
  $("#sync-preview-button").onclick = () => openSyncDialog();
  $("#sync-close").onclick = closeSyncDialog;
  $("#sync-dismiss").onclick = closeSyncDialog;
  $("#sync-dialog").addEventListener("cancel", (event) => { event.preventDefault(); closeSyncDialog(); });
  $("#sync-reload").onclick = loadSyncPreview;
  $("#sync-start").onclick = startSync;
  $("#sync-cancel-job").onclick = cancelSyncJob;
  $("#sync-retry-status").onclick = resumeSyncStatus;
  $("#sync-search").oninput = (event) => {
    event.target.rows = Math.min(4, Math.max(1, event.target.value.split(/\r\n|\r|\n/).length));
    state.sync.search = event.target.value.trim();
    state.sync.page = 1;
    renderSyncPreview();
  };
  $("#sync-select-all").onchange = (event) => {
    if (syncRunning() || state.sync.loading) return;
    const ready = state.sync.preview.filter(syncCanImport);
    state.sync.selected = event.target.checked ? new Set(ready.slice(0, SYNC_BATCH_LIMIT).map((item) => item.source_key)) : new Set();
    showSyncError(event.target.checked && ready.length > SYNC_BATCH_LIMIT ? `单次最多同步 ${SYNC_BATCH_LIMIT} 个来源，已选择本批前 ${SYNC_BATCH_LIMIT} 个，其余来源留待下批同步。` : "");
    renderSync();
  };
  $("#sync-preview-rows").onchange = (event) => {
    const control = event.target.closest("[data-sync-index]");
    if (!control || syncRunning()) return;
    const item = state.sync.preview[Number(control.dataset.syncIndex)];
    if (!item || !syncCanImport(item)) return;
    if (control.checked && !state.sync.selected.has(item.source_key) && state.sync.selected.size >= SYNC_BATCH_LIMIT) {
      control.checked = false;
      showSyncError(`单次最多同步 ${SYNC_BATCH_LIMIT} 个来源，请先取消其他选择，或将此来源留待下批同步。`);
      renderSync();
      return;
    }
    showSyncError();
    if (control.checked) state.sync.selected.add(item.source_key);
    else state.sync.selected.delete(item.source_key);
    renderSync();
  };
  $("#sync-prev").onclick = () => { state.sync.page--; renderSyncPreview(); };
  $("#sync-next").onclick = () => { state.sync.page++; renderSyncPreview(); };
  $$(".list-tab").forEach(
    (button) =>
      (button.onclick = () => {
        state.filter = button.dataset.filter;
        state.page = 1;
        $$(".list-tab").forEach((el) => {
          const active = el === button;
          el.classList.toggle("active", active);
          el.setAttribute("aria-selected", String(active));
        });
        renderProfiles();
      }),
  );
  $("#search-input").oninput = scheduleProfileSearch;
  $("#search-input").oncompositionstart = () => {
    profileSearchComposing = true;
    cancelProfileSearch();
  };
  $("#search-input").oncompositionend = (event) => {
    profileSearchComposing = false;
    scheduleProfileSearch(event);
  };
  $("#group-filter").onchange = (event) => {
    state.group = event.target.value;
    state.page = 1;
    renderProfiles();
  };
  $("#tag-filter").onchange = (event) => {
    state.tag = event.target.value;
    state.page = 1;
    renderProfiles();
  };
  $("#clear-filters").onclick = () => {
    cancelProfileSearch();
    state.search = "";
    state.group = "";
    state.tag = "";
    state.page = 1;
    $("#search-input").value = "";
    $("#search-input").rows = 1;
    renderFilters();
    renderProfiles();
  };
  $("#arrange-windows").onclick = arrangeWindows;
  $("#window-layout-settings").onclick = openWindowLayout;
  $("#window-layout-close").onclick = closeWindowLayout;
  $("#window-layout-cancel").onclick = closeWindowLayout;
  $("#window-layout-dialog").addEventListener("cancel", (event) => { event.preventDefault(); closeWindowLayout(); });
  $("#window-layout-mode").onchange = renderWindowLayout;
  $("#window-layout-form").onsubmit = (event) => { event.preventDefault(); saveWindowLayout(); };
  $("#window-layout-save").onclick = () => saveWindowLayout();
  $("#window-layout-save-arrange").onclick = () => saveWindowLayout(true);
  $$("[data-sort]").forEach(
    (button) =>
      (button.onclick = () => {
        state.direction =
          state.sort === button.dataset.sort ? -state.direction : 1;
        state.sort = button.dataset.sort;
        state.page = 1;
        renderProfiles();
      }),
  );
  $("#page-size").onchange = (event) => {
    state.pageSize = Number(event.target.value);
    state.page = 1;
    renderProfiles();
  };
  $("#prev-page").onclick = () => {
    state.page--;
    renderProfiles();
  };
  $("#next-page").onclick = () => {
    state.page++;
    renderProfiles();
  };
  $("#select-all").onchange = (event) => {
    if (state.deleteBusy) return;
    filteredProfiles()
      .slice((state.page - 1) * state.pageSize, state.page * state.pageSize)
      .forEach((profile) =>
        event.target.checked
          ? state.selected.add(String(profile.id))
          : state.selected.delete(String(profile.id)),
      );
    renderProfiles();
  };
  $("#clear-selection").onclick = () => {
    if (state.deleteBusy) return;
    state.selected.clear();
    renderProfiles();
  };
  $$("[data-batch]").forEach(
    (button) =>
      (button.onclick = () => batchAction(button.dataset.batch, button)),
  );
  $("#profile-rows").addEventListener("change", (event) => {
    if (state.deleteBusy || !event.target.matches(".row-check")) return;
    event.target.checked
      ? state.selected.add(event.target.dataset.id)
      : state.selected.delete(event.target.dataset.id);
    renderProfiles();
  });
  $("#profile-rows").addEventListener("focusout", () => {
    if (!state.profileRenderPending) return;
    clearTimeout(state.profileFocusTimer);
    state.profileFocusTimer = setTimeout(() => {
      state.profileFocusTimer = null;
      if (state.profileRenderPending && !$("#profile-rows").contains(document.activeElement)) renderProfiles();
    }, 0);
  });
  $("#profile-rows").addEventListener("click", (event) => {
    const button = event.target.closest("[data-action]");
    if (!button) return;
    if (button.dataset.action === "menu")
      openRowMenu(button.dataset.id, button);
    else performAction(button.dataset.action, button.dataset.id);
  });
  $("#row-menu").onclick = (event) => {
    const button = event.target.closest("[data-menu-action]");
    if (!button) return;
    $("#row-menu").hidden = true;
    performAction(button.dataset.menuAction, button.dataset.id);
  };
  document.addEventListener("click", (event) => {
    if (!event.target.closest('#row-menu,[data-action="menu"]'))
      $("#row-menu").hidden = true;
  });
  window.addEventListener("resize", () => {
    $("#row-menu").hidden = true;
  });
  document.addEventListener(
    "scroll",
    (event) => {
      if (event.target !== $("#row-menu")) $("#row-menu").hidden = true;
    },
    true,
  );
  $("#drawer-nav").onclick = (event) => {
    const button = event.target.closest("[data-section]");
    if (button && !state.saving) setDrawerSection(button.dataset.section);
  };
  $("#profile-form").addEventListener("input", (event) => {
    if (event.target.matches("[data-field]")) readField(event.target);
  });
  $("#profile-form").addEventListener("change", (event) => {
    if (event.target.matches("[data-field]")) readField(event.target);
    if (
      event.target.dataset.field === "proxy.host" &&
      hasProxyAddress(event.target.value)
    ) parseProxyText(event.target.value);
    if (event.target.id === "cookie-file-input")
      readCookieFile(event.target.files?.[0]);
  });
  $("#profile-form").addEventListener("paste", (event) => {
    if (event.target.dataset.field !== "proxy.host" || state.saving) return;
    const text = event.clipboardData?.getData("text") || "";
    if (!hasProxyAddress(text)) return;
    event.preventDefault();
    parseProxyText(text);
  });
  $("#profile-form").onsubmit = (event) => {
    event.preventDefault();
    saveProfile();
  };
  $("#profile-form").addEventListener("click", (event) => {
    if (event.target.closest("#creation-randomize")) randomizeCreation();
    const reveal = event.target.closest("[data-reveal]");
    if (reveal) {
      const input = document.getElementById(reveal.dataset.reveal);
      input.type = input.type === "password" ? "text" : "password";
      return;
    }
    if (event.target.closest("#drawer-proxy-test"))
      testProxy(null, $("#drawer-proxy-test"), $("#drawer-proxy-result"));
    if (event.target.closest("#import-cookie")) $("#cookie-file-input").click();
  });
  $("#save-profile").onclick = saveProfile;
  $("#close-drawer").onclick = closeDrawer;
  $("#cancel-drawer").onclick = closeDrawer;
  $("#drawer-backdrop").onclick = closeDrawer;
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || $("#confirm-dialog").open) return;
    if ($("#sync-dialog").open || $("#window-layout-dialog").open) return;
    if (!$("#row-menu").hidden) {
      $("#row-menu").hidden = true;
      event.preventDefault();
    } else if (!$("#profile-drawer").hidden) {
      event.preventDefault();
      closeDrawer();
    }
  });
  $("#add-group").onclick = () => {
    if (state.groupsSaving) return;
    state.groupDraft.push("");
    state.groupSources.push(null);
    renderGroups();
    $$("[data-group-index]").at(-1)?.focus();
  };
  $("#group-list").addEventListener("input", (event) => {
    if (state.groupsSaving) return;
    if (event.target.matches("[data-group-index]"))
      state.groupDraft[Number(event.target.dataset.groupIndex)] =
        event.target.value;
  });
  $("#group-list").onclick = async (event) => {
    if (state.groupsSaving) return;
    const button = event.target.closest("[data-remove-group]");
    if (!button) return;
    const index = Number(button.dataset.removeGroup);
    const draft = state.groupDraft;
    const group = draft[index];
    if (
      !(await confirmAction(
        "移除分组",
        "分组内的窗口将由本地服务移到未分组，窗口资料会保留。",
        "移除分组",
      ))
    )
      return;
    if (state.groupsSaving || state.panel !== "groups" || state.groupDraft !== draft || draft[index] !== group) return;
    state.groupDraft.splice(index, 1);
    state.groupSources.splice(index, 1);
    renderGroups();
  };
  $("#save-groups").onclick = saveGroups;
  $("#proxy-list").onclick = (event) => {
    const edit = event.target.closest("[data-proxy-edit]");
    if (edit) openDrawer(profileById(edit.dataset.proxyEdit), "proxy");
    const test = event.target.closest("[data-proxy-test]");
    if (test)
      testProxy(
        test.dataset.proxyTest,
        test,
        $$("[data-proxy-result]").find(
          (el) => el.dataset.proxyResult === test.dataset.proxyTest,
        ),
      );
  };
  $("#recycle-list").onclick = (event) => {
    const deletion = event.target.closest("[data-delete]");
    if (deletion) { performAction("delete", deletion.dataset.delete); return; }
    const button = event.target.closest("[data-restore]");
    if (button) performAction("restore", button.dataset.restore);
  };
  $("#recycle-list").addEventListener("change", (event) => {
    if (state.batchBusy || state.deleteBusy || !event.target.matches("[data-recycle-select]")) return;
    const id = event.target.dataset.recycleSelect;
    const profile = profileById(id);
    if (!profile || !isArchived(profile)) return;
    if (event.target.checked) state.recycleSelected.add(String(id));
    else state.recycleSelected.delete(String(id));
    renderRecycle();
  });
  $("#recycle-select-all").onchange = (event) => {
    if (state.batchBusy || state.deleteBusy) return;
    state.recycleSelected = event.target.checked ? new Set(state.profiles.filter(isArchived).map((profile) => String(profile.id))) : new Set();
    renderRecycle();
  };
  $("#recycle-delete-selected").onclick = () => batchAction("delete", $("#recycle-delete-selected"), { recycle: true });
  $("#refresh-recycle").onclick = async () => {
    try {
      await refreshProfiles();
      renderRecycle();
    } catch (error) {
      toast(error.message, "error");
    }
  };
  $("#settings-form").addEventListener("input", (event) => {
    if (event.target.matches("[data-setting]")) {
      state.settingsDraft[event.target.dataset.setting] =
        event.target.type === "checkbox"
          ? event.target.checked
          : event.target.value;
      state.settingsDirty = true;
      state.settingsDraftRevision++;
    }
  });
  $("#settings-form").addEventListener("change", (event) => {
    if (event.target.matches("[data-setting]")) {
      state.settingsDraft[event.target.dataset.setting] =
        event.target.type === "checkbox"
          ? event.target.checked
          : event.target.value;
      state.settingsDirty = true;
      state.settingsDraftRevision++;
    }
  });
  $("#settings-form").onclick = (event) => {
    const button = event.target.closest("[data-choose]");
    if (button) chooseSetting(button.dataset.choose, button);
  };
  $("#save-settings").onclick = saveSettings;
  $("#export-button").onclick = () =>
    exportProfiles($("#export-button"));
}
async function readCookieFile(file) {
  const request = ++state.cookieReadRequest;
  const input = $("#cookie-file-input");
  const clearInput = () => {
    if (input && (state.cookieReadRequest === request || $("#cookie-file-input") !== input)) input.value = "";
  };
  if (!file || !state.draft) {
    clearInput();
    return;
  }
  const draft = state.draft;
  const session = state.drawerSession;
  const current = () => state.cookieReadRequest === request && state.draft === draft && state.drawerSession === session && !$("#profile-drawer").hidden && !state.saving;
  if (file.size > 5 * 1024 * 1024) {
    toast("Cookie 文件不能超过 5 MB。", "error");
    clearInput();
    return;
  }
  try {
    const text = await file.text();
    if (!current()) return;
    draft.cookie_text = text;
    state.dirty = true;
    $("#field-cookie_text").value = text;
    toast("已读取 Cookie 文本，保存窗口后应用。", "success");
  } catch {
    if (current()) toast("无法读取此文件，请确认文件可访问并重试。", "error");
  } finally {
    clearInput();
  }
}

hydrateIcons();
bindEvents();
renderProfiles();
let initialized = false;
function initializeBridge() {
  if (initialized || !apiAvailable()) return;
  initialized = true;
  bootstrap({ quiet: true }).then(async () => {
    if (!state.settingsLoaded) {
      try {
        const revision = state.settingsRevision;
        const settings = await api("settings_get");
        if (revision === state.settingsRevision && !state.settingsSaving) {
          state.settings = settings?.settings || settings || {};
          state.settingsLoaded = true;
        }
      } catch {
        /* The settings panel presents its own read error. */
      }
    }
    scheduleStatusRefresh();
  });
}
document.addEventListener("visibilitychange", () => {
  clearTimeout(state.statusTimer);
  if (!document.hidden && initialized) refreshStatus();
});
window.addEventListener("pywebviewready", initializeBridge);
initializeBridge();
if (!initialized) {
  let attempts = 0;
  const connectionTimer = setInterval(() => {
    attempts++;
    initializeBridge();
    if (initialized || attempts >= 40) {
      clearInterval(connectionTimer);
      if (!initialized) {
        setConnection(false);
        showServiceError(
          "尚未连接到本地服务。请通过桌面程序启动；此界面需要本地服务才能保存和打开浏览器窗口。",
        );
      }
    }
  }, 250);
}
