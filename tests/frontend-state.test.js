"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "app/ui/app.js"), "utf8");
const entry = source.lastIndexOf("\nhydrateIcons();");
assert.ok(entry > 0, "The fixture must stop before desktop initialization.");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test("independent import discloses first enrollment when historical seed is missing", () => {
  const { context } = fixture();
  const profile = { signature_provider: "local-v1", environment_check: true };
  assert.doesNotMatch(context.signatureNoticeText(profile), /无法保证还原/);
  profile.import_notes = ["原厂未保留历史运行种子，使用对应版本公开签名种子首次登记"];
  assert.match(context.signatureNoticeText(profile), /无法保证还原更早一次运行/);
  profile.import_notes = "unexpected";
  assert.doesNotThrow(() => context.signatureNoticeText(profile));
});

test("new window entry preserves source sync and keeps imported fingerprints read-only", async () => {
  const h=fixture();
  h.context.window.crypto={randomUUID:()=>"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"};
  h.context.api=async(action)=>({cores:["104","148"],defaults:{name:"新窗口",fingerprint:{coreVersion:"148"}}});
  await h.context.openCreation(true);
  assert.equal(h.state.creatingDraft,true);
  assert.equal(h.state.draft.creation.count,10);
  assert.equal(h.state.creation.requestId,"aaaaaaaabbbbccccddddeeeeeeeeeeee");
  assert.ok(h.element("#create-button").onclick);
  await h.context.closeDrawer();
  h.context.openDrawer({id:"existing",name:"existing",fingerprint:{coreVersion:"148"}});
  assert.equal(h.state.creatingDraft,false);
  assert.match(source,/control.disabled = !state.creatingDraft/);
});

test("port scan protection labels preserve the native mode values", () => {
  const h = fixture();
  for (const [mode, label] of [["0", "启用"], ["1", "关闭"]]) {
    h.state.draft = h.context.mergedProfile({ fingerprint: { portScanProtect: mode } });
    h.state.creatingDraft = true;
    h.context.buildProfileForm();
    const select = h.element("#profile-form").innerHTML.match(/<select id="field-fingerprint-portScanProtect"[^>]*>(.*?)<\/select>/s);
    assert.ok(select);
    assert.match(select[1], new RegExp(`<option value="${mode}" selected>${label}</option>`));
    h.context.readField({ dataset: { field: "fingerprint.portScanProtect", type: "string" }, value: mode });
    assert.equal(h.state.draft.fingerprint.portScanProtect, mode);
  }
});

test("explicit creation device changes apply the stock mobile screen defaults and preserve later manual edits", () => {
  const h = fixture();
  const catalog = JSON.parse(fs.readFileSync(path.join(root, "app/resources/creation-catalog.json"), "utf8"));
  h.state.creatingDraft = true;
  h.state.creation.resolutions = catalog.MobileResolutions;
  h.state.creation.presets = catalog.Presets;
  h.state.creation.builds = catalog.BuildVersions;
  h.state.draft = h.context.mergedProfile({ fingerprint: { coreVersion: "104", ostype: "PC", os: "Win32" } });
  const edit = (field, value) => h.context.readField({ dataset: { field: "fingerprint." + field, type: "string" }, value });
  for (const [device, dpr] of [["Android", 2], ["IOS", 3]]) {
    edit("ostype", device);
    const fp = h.state.draft.fingerprint;
    assert.equal(fp.openWidth, 500);
    assert.equal(fp.openHeight, 950);
    assert.equal(fp.devicePixelRatio, dpr);
    assert.equal(fp.resolutionType, "1");
    assert.ok(catalog.MobileResolutions[device].includes(fp.resolution));
    assert.equal(h.element("#field-fingerprint-resolution").value, fp.resolution);
    edit("resolution", "400x850");
    edit("devicePixelRatio", 2.5);
    edit("openWidth", 520);
    edit("openHeight", 980);
    edit("coreVersion", fp.coreVersion === "104" ? "148" : "104");
    assert.equal(fp.resolution, "400x850");
    assert.equal(fp.devicePixelRatio, 2.5);
    assert.equal(fp.openWidth, 520);
    assert.equal(fp.openHeight, 980);
  }
  edit("ostype", "PC");
  const fp = h.state.draft.fingerprint;
  assert.equal(fp.openWidth, 1280);
  assert.equal(fp.openHeight, 720);
  assert.equal(fp.devicePixelRatio, 1);
  assert.equal(fp.resolutionType, "0");
  assert.equal(fp.resolution, "1920x1080");
  const before = JSON.stringify(h.state.draft);
  h.state.creatingDraft = false;
  h.context.readField({ disabled: true, dataset: { field: "fingerprint.ostype", type: "string" }, value: "Android" });
  assert.equal(JSON.stringify(h.state.draft), before);
});

test("creation with an interrupted task opens its progress instead of a second draft", async () => {
  const h=fixture();
  h.context.api=async(action)=>({latest:{job_id:"fixture",state:"interrupted",total:3,completed:1,failed:0,items:[]}});
  h.context.pollCreation=async()=>{};
  await h.context.openCreation();
  assert.equal(h.state.creation.job.job_id,"fixture");
  assert.equal(h.element("#creation-dialog").open,true);
  assert.equal(h.state.draft,null);
});

test("failed creation keeps an accessible retry and explicit cancel", async () => {
  const h=fixture();
  h.context.api=async()=>({latest:{job_id:"failed",state:"failed",total:2,completed:1,failed:1,items:[]}});
  h.context.pollCreation=async()=>{};
  await h.context.openCreation();
  assert.equal(h.state.draft,null);
  assert.equal(h.element("#creation-cancel").hidden,false);
  assert.equal(h.element("#creation-resume").hidden,false);
});

test("creation completed before its submission response refreshes the new window list", async () => {
  const h=fixture();
  const job={job_id:"fixture",state:"completed",total:1,completed:1,failed:0,items:[]};
  let refreshes=0;
  h.context.api=async()=>job;
  h.context.refreshProfiles=async()=>refreshes++;
  h.context.pollCreation=async()=>{};
  await h.context.submitCreation({name:"synthetic",creation:{count:1}});
  assert.equal(refreshes,1);
  assert.equal(h.state.creation.job.state,"completed");
  assert.equal(h.element("#creation-dialog").open,true);
  assert.equal(h.state.saving,false);
});

test("cancel recognizing a committed window and immediate resume completion refresh the list", async () => {
  for (const [action,state] of [["cancel_creation","cancelled"],["resume_creation","completed"]]) {
    const h=fixture();
    const job={job_id:"fixture",state:"interrupted",total:2,completed:0,failed:0,items:[]};
    let refreshes=0;
    h.context.acceptCreationJob(job);
    h.context.api=async()=>({...job,state,completed:1,cancel_requested:state==="cancelled"});
    h.context.refreshProfiles=async()=>refreshes++;
    await h.context.mutateCreation(action);
    assert.equal(refreshes,1);
    assert.equal(h.state.creation.job.state,state);
    assert.equal(h.state.creation.job.completed,1);
    assert.equal(h.state.creation.mutating,false);
  }
});

test("a list refresh failure keeps the confirmed creation result", async () => {
  const h=fixture();
  h.context.api=async()=>({job_id:"fixture",state:"completed",total:1,completed:1,failed:0,items:[]});
  h.context.refreshProfiles=async()=>{throw new Error("synthetic failure");};
  h.context.pollCreation=async()=>{};
  await h.context.submitCreation({name:"synthetic",creation:{count:1}});
  assert.equal(h.state.creation.job.state,"completed");
  assert.equal(h.state.draft,null);
  assert.equal(h.element("#creation-error").hidden,false);
  assert.doesNotMatch(h.element("#creation-error").textContent,/结果未确认/);
});

test("late creation status cannot roll back a confirmed cancel", async () => {
  const h=fixture(),pending=deferred();
  const job={job_id:"fixture",state:"running",total:3,completed:1,failed:0,items:[]};
  h.context.acceptCreationJob(job);
  h.context.api=async(action)=>action==="creation_status"?pending.promise:{...job,state:"cancelled",cancel_requested:true};
  const polling=h.context.pollCreation();
  await h.context.mutateCreation("cancel_creation");
  pending.resolve({...job,completed:0});await polling;
  assert.equal(h.state.creation.job.state,"cancelled");
  assert.equal(h.state.creation.job.completed,1);
  assert.equal(h.state.creation.reading,false);
});

test("late bootstrap cannot replace newer creation progress", async () => {
  const h=fixture(),pending=deferred();
  h.context.api=async()=>pending.promise;
  const reading=h.context.bootstrap({quiet:true});
  h.context.acceptCreationJob({job_id:"new",state:"completed",total:1,completed:1,failed:0,items:[]});
  pending.resolve({creation_job:null});await reading;
  assert.equal(h.state.creation.job.job_id,"new");
});

test("missing creation status clears deleted history and stops polling", async () => {
  const h=fixture();
  h.context.acceptCreationJob({job_id:"deleted",state:"running",total:1,completed:0,failed:0,items:[]});
  h.context.api=async(action,payload)=>{assert.equal(action,"creation_status");assert.equal(payload.missing_ok,true);return null;};
  await h.context.pollCreation(true);
  assert.equal(h.state.creation.job,null);
  assert.equal(h.element("#creation-progress-button").hidden,true);
  assert.equal(h.timers.size,0);
});

test("uncertain creation submission retries the same request with an intact draft", async () => {
  const h=fixture(),requests=[];
  h.state.creatingDraft=true;h.state.creation.requestId="a".repeat(32);
  h.state.draft={name:"synthetic",fingerprint:{},creation:{count:2,random_each:true,proxy_lines:[]}};
  h.context.api=async(action,payload)=>{requests.push(JSON.parse(JSON.stringify(payload)));throw new Error("synthetic failure");};
  for(let i=0;i<2;i++)await h.context.submitCreation(JSON.parse(JSON.stringify(h.state.draft)));
  assert.deepEqual(requests[0],requests[1]);
  assert.equal(h.state.draft.creation.count,2);
  assert.equal(h.state.saving,false);
});

function fixture() {
  const nodes = new Map();
  const timers = new Map();
  let nextTimer = 0;
  const element = (selector) => {
    if (!nodes.has(selector)) {
      nodes.set(selector, {
        hidden: true, disabled: false, inert: false, value: "", textContent: "",
        innerHTML: "", style: {}, dataset: {}, listeners: new Map(), all: new Map(),
        classList: { toggle() {}, add() {}, contains() { return false; } },
        setAttribute(key, value) { this[key] = value; },
        addEventListener(type, callback) { this.listeners.set(type, callback); },
        querySelectorAll(query) { return this.all.get(query) || []; },
        querySelector() { return null; },
        contains() { return false; }, focus() {}, scrollTo() {}, scrollIntoView() {},
        showModal() { this.open = true; }, close() { this.open = false; },
      });
    }
    return nodes.get(selector);
  };
  const context = vm.createContext({
    document: {
      querySelector: element, querySelectorAll() { return []; },
      addEventListener() {}, activeElement: null, hidden: false, body: { style: {} },
    },
    window: { addEventListener() {} },
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(source.slice(0, entry), context, { filename: "app/ui/app.js" });
  vm.runInContext(source.slice(source.indexOf("let initialized = false;"),
    source.indexOf('document.addEventListener("visibilitychange"')), context);
  const renderProfiles = context.renderProfiles;
  const refreshProfiles = context.refreshProfiles;
  const nativeConfirmAction = context.confirmAction;
  const state = vm.runInContext("state", context);
  const toasts = [], confirmations = [], serviceErrors = [];
  context.toast = (message, type) => toasts.push({ message, type });
  context.confirmAction = async (title) => { confirmations.push(title); return true; };
  context.showServiceError = (message) => serviceErrors.push(message);
  context.renderProfiles = () => {};
  context.renderFilters = () => {};
  context.renderGroups = () => {};
  context.renderPanel = async () => {};
  context.refreshProfiles = async () => {};
  context.api = async () => ({});
  context.bindEvents();
  const setting = (key, value) => element("#settings-form").listeners.get("input")({
    target: {
      matches: () => true, dataset: { setting: key },
      type: typeof value === "boolean" ? "checkbox" : "text", checked: value, value,
    },
  });
  return { context, state, element, nodes, timers, toasts, confirmations, serviceErrors, setting, renderProfiles, refreshProfiles, nativeConfirmAction };
}

test("discarded settings never change single or batch close confirmation", async () => {
  const h = fixture();
  h.state.settings = { confirm_close: true };
  h.state.settingsDraft = { confirm_close: true };
  h.state.panel = "settings";
  h.setting("confirm_close", false);
  assert.equal(h.state.settings.confirm_close, true);
  assert.equal(h.state.settingsDraft.confirm_close, false);
  await h.context.navigate("profiles");
  assert.equal(h.state.settingsDirty, false);
  assert.equal(h.state.settingsDraft.confirm_close, true);
  h.state.profiles = [{ id: "fixture", name: "Fixture", status: "running" }];
  h.confirmations.length = 0;
  await h.context.performAction("close", "fixture");
  assert.deepEqual(h.confirmations, ["关闭浏览器"]);
  h.state.selected.add("fixture");
  h.context.api = async () => ({ completed: 1, errors: [] });
  await h.context.batchAction("close", h.element("batch"));
  assert.deepEqual(h.confirmations, ["关闭浏览器", "批量关闭窗口"]);
});

test("settings save uses a snapshot and preserves edits made during the request", async () => {
  const h = fixture(), pending = deferred();
  h.state.settings = { start_page: "saved" };
  h.state.settingsDraft = { start_page: "submitted" };
  h.state.settingsDirty = true;
  let calls = 0, submitted;
  h.context.api = async (_, payload) => {
    calls++; submitted = payload.settings;
    await pending.promise;
    return { settings: submitted };
  };
  const saving = h.context.saveSettings();
  await h.context.saveSettings();
  assert.equal(calls, 1);
  const focused = h.element("#settings-start_page");
  h.context.document.activeElement = focused;
  h.setting("start_page", "newer draft");
  pending.resolve();
  await saving;
  assert.equal(submitted.start_page, "submitted");
  assert.equal(h.state.settings.start_page, "submitted");
  assert.equal(h.state.settingsDraft.start_page, "newer draft");
  assert.equal(h.state.settingsDirty, true);
  assert.equal(h.context.document.activeElement, focused);
  assert.equal(h.element("#settings-start_page"), focused);
  h.context.api = async (_, payload) => ({ settings: payload.settings });
  await h.context.saveSettings();
  assert.equal(h.state.settings.start_page, "newer draft");
  assert.equal(h.state.settingsDirty, false);
  assert.equal(h.state.settingsSaving, false);
});

test("failed settings save retains the saved policy and unsaved draft", async () => {
  const h = fixture();
  h.state.settings = { confirm_close: true };
  h.state.settingsDraft = { confirm_close: false };
  h.state.settingsDirty = true;
  h.context.api = async () => { throw new Error("Fixture failure"); };
  await h.context.saveSettings();
  assert.equal(h.state.settings.confirm_close, true);
  assert.equal(h.state.settingsDraft.confirm_close, false);
  assert.equal(h.state.settingsDirty, true);
  assert.equal(h.element("#save-settings").disabled, false);
});

test("late path selection cannot overwrite a replacement settings draft", async () => {
  const h = fixture(), pending = deferred();
  h.state.panel = "settings";
  h.state.settingsDraft = { download_dir: "first" };
  h.context.api = async () => pending.promise;
  const choosing = h.context.chooseSetting("download_dir", h.element("choose"));
  h.state.settingsDraft = { download_dir: "second" };
  pending.resolve({ path: "fixture path" });
  await choosing;
  assert.equal(h.state.settingsDraft.download_dir, "second");
  assert.equal(h.state.settingsDirty, false);
});

test("Cookie file read is bound to both the original draft and drawer session", async () => {
  for (const replaceDraft of [true, false]) {
    const h = fixture(), pending = deferred();
    const draft = { id: "first", cookie_text: "unchanged" };
    h.state.draft = draft;
    h.state.drawerSession = 1;
    h.element("#profile-drawer").hidden = false;
    const originalInput = h.element("#cookie-file-input");
    originalInput.value = "fixture selection";
    const reading = h.context.readCookieFile({ size: 1, text: () => pending.promise });
    if (replaceDraft) h.state.draft = { id: "second", cookie_text: "unchanged" };
    else h.state.drawerSession++;
    h.nodes.delete("#cookie-file-input");
    const newInput = h.element("#cookie-file-input");
    newInput.value = "new selection";
    pending.resolve("fixture-cookie");
    await reading;
    assert.equal(h.state.draft.cookie_text, "unchanged");
    assert.equal(h.state.dirty, false);
    assert.equal(newInput.value, "new selection");
    assert.equal(originalInput.value, "");
    assert.equal(h.toasts.length, 0);
  }
});

test("Cookie file success and size limit retain their existing behavior", async () => {
  const h = fixture();
  h.state.draft = { id: "fixture" };
  h.element("#profile-drawer").hidden = false;
  await h.context.readCookieFile({ size: 1, text: async () => "fixture-cookie" });
  assert.equal(h.state.draft.cookie_text, "fixture-cookie");
  assert.equal(h.state.dirty, true);
  let read = false;
  await h.context.readCookieFile({ size: 5 * 1024 * 1024 + 1, text() { read = true; } });
  assert.equal(read, false);
  assert.equal(h.toasts.at(-1).type, "error");
});

test("only the latest Cookie file selection can apply when reads finish in reverse order", async () => {
  const h = fixture(), first = deferred(), second = deferred();
  h.state.draft = { id: "fixture", cookie_text: "unchanged" };
  h.element("#profile-drawer").hidden = false;
  const older = h.context.readCookieFile({ size: 1, text: () => first.promise });
  const newer = h.context.readCookieFile({ size: 1, text: () => second.promise });
  second.resolve("newer fixture"); await newer;
  first.resolve("older fixture"); await older;
  assert.equal(h.state.draft.cookie_text, "newer fixture");
  assert.equal(h.element("#field-cookie_text").value, "newer fixture");
  assert.equal(h.toasts.length, 1);
});

test("a newer failed, oversized or cleared Cookie selection invalidates an older read", async () => {
  for (const selection of ["failure", "oversized", "cleared"]) {
    const h = fixture(), first = deferred();
    h.state.draft = { id: "fixture", cookie_text: "unchanged" };
    h.element("#profile-drawer").hidden = false;
    const older = h.context.readCookieFile({ size: 1, text: () => first.promise });
    const input = h.element("#cookie-file-input"); input.value = "new selection";
    await h.context.readCookieFile(selection === "cleared" ? undefined : {
      size: selection === "oversized" ? 5 * 1024 * 1024 + 1 : 1,
      text: async () => { throw new Error("Fixture read failure"); },
    });
    first.resolve("older fixture"); await older;
    assert.equal(h.state.draft.cookie_text, "unchanged", selection);
    assert.equal(h.state.dirty, false, selection);
    assert.equal(h.toasts.length, selection === "cleared" ? 0 : 1, selection);
  }
});

test("an old Cookie read failure cannot clear a newer pending file selection", async () => {
  const h = fixture(), first = deferred(), second = deferred();
  h.state.draft = { id: "fixture", cookie_text: "unchanged" };
  h.element("#profile-drawer").hidden = false;
  const older = h.context.readCookieFile({ size: 1, text: () => first.promise });
  const input = h.element("#cookie-file-input"); input.value = "new selection";
  const newer = h.context.readCookieFile({ size: 1, text: () => second.promise });
  first.reject(new Error("Fixture stale failure")); await older;
  assert.equal(input.value, "new selection");
  assert.equal(h.toasts.length, 0);
  second.resolve("newer fixture"); await newer;
  assert.equal(input.value, "");
  assert.equal(h.state.draft.cookie_text, "newer fixture");
});

test("manual Cookie text editing invalidates a pending file read", async () => {
  const h = fixture(), pending = deferred();
  h.state.draft = { id: "fixture", cookie_text: "unchanged" };
  h.element("#profile-drawer").hidden = false;
  const reading = h.context.readCookieFile({ size: 1, text: () => pending.promise });
  h.context.readField({
    disabled: false, dataset: { field: "cookie_text", type: "string" }, value: "manual fixture",
  });
  pending.resolve("file fixture"); await reading;
  assert.equal(h.state.draft.cookie_text, "manual fixture");
  assert.equal(h.toasts.length, 0);
});

test("batch processes all 205 selections in sequential groups of at most 100", async () => {
  const h = fixture(), sizes = [], seen = [];
  for (let i = 0; i < 205; i++) h.state.selected.add(`fixture-${i}`);
  let active = 0, maximum = 0, refreshed = 0;
  h.context.api = async (action, payload) => {
    assert.equal(action, "batch");
    assert.equal(h.state.batchBusy, true);
    assert.equal(h.state.operationIds.size, 205);
    active++; maximum = Math.max(maximum, active);
    sizes.push(payload.ids.length); seen.push(...payload.ids);
    await Promise.resolve(); active--;
    return sizes.length === 2
      ? { completed: 99, errors: [{ error: "Fixture failure" }] }
      : { completed: payload.ids.length, errors: [] };
  };
  h.context.refreshProfiles = async () => { refreshed++; assert.equal(h.state.batchBusy, true); };
  const button = h.element("batch"); button.textContent = "打开";
  await h.context.batchAction("open", button);
  assert.deepEqual(sizes, [100, 100, 5]);
  assert.equal(new Set(seen).size, 205);
  assert.equal(maximum, 1);
  assert.equal(refreshed, 1);
  assert.match(h.toasts.at(-1).message, /成功 204 个，失败 1 个/);
  assert.equal(h.state.batchBusy, false);
  assert.equal(h.state.operationIds.size, 0);
  assert.equal(button.textContent, "打开");
});

test("a concurrent batch is ignored and an interrupted batch reports uncertain results", async () => {
  const h = fixture(), pending = deferred();
  for (let i = 0; i < 205; i++) h.state.selected.add(`fixture-${i}`);
  let calls = 0, refreshed = 0;
  h.context.api = async () => {
    calls++;
    if (calls === 1) { await pending.promise; return { completed: 100, errors: [] }; }
    throw new Error("Fixture interruption");
  };
  h.context.refreshProfiles = async () => { refreshed++; };
  const first = h.context.batchAction("open", h.element("batch"));
  await h.context.batchAction("open", h.element("second batch"));
  assert.equal(calls, 1);
  pending.resolve(); await first;
  assert.equal(calls, 2);
  assert.equal(refreshed, 1);
  assert.match(h.toasts.at(-1).message, /已确认成功 100 个.*105 个结果未确认/);
  assert.equal(h.state.batchBusy, false);
  assert.equal(h.state.operationIds.size, 0);
});

test("list refresh failure does not turn confirmed batch success into operation failure", async () => {
  const h = fixture(); h.state.selected.add("fixture");
  h.context.api = async () => ({ completed: 1, errors: [] });
  h.context.refreshProfiles = async () => { throw new Error("Fixture refresh failure"); };
  await h.context.batchAction("open", h.element("batch"));
  assert.equal(h.toasts.length, 1);
  assert.equal(h.toasts[0].type, "success");
  assert.match(h.serviceErrors[0], /列表刷新失败/);
  assert.equal(h.state.batchBusy, false);
});

test("group saving prevents edits and navigation until the snapshot is committed", async () => {
  const h = fixture(), pending = deferred();
  h.state.panel = "groups";
  h.state.groupDraft = ["First"];
  h.state.groupOriginal = ["First"];
  h.state.groupSources = ["First"];
  h.context.api = async () => { await pending.promise; return {}; };
  const saving = h.context.saveGroups();
  h.element("#group-list").listeners.get("input")({
    target: { matches: () => true, dataset: { groupIndex: "0" }, value: "Second" },
  });
  h.element("#add-group").onclick();
  await h.element("#group-list").onclick({
    target: { closest: () => ({ dataset: { removeGroup: "0" } }) },
  });
  assert.equal(h.confirmations.length, 0);
  await h.context.navigate("profiles");
  assert.deepEqual(Array.from(h.state.groupDraft), ["First"]);
  assert.equal(h.state.panel, "groups");
  assert.equal(h.element("#group-list").inert, true);
  pending.resolve(); await saving;
  assert.equal(h.state.groupsSaving, false);
  assert.equal(h.element("#group-list").inert, false);
  assert.equal(h.element("#add-group").disabled, false);
});

test("late group removal confirmation cannot edit a replacement group draft", async () => {
  const h = fixture(), pending = deferred();
  h.state.panel = "groups";
  h.state.groupDraft = ["First"];
  h.state.groupSources = ["First"];
  h.context.confirmAction = async () => pending.promise;
  const removing = h.element("#group-list").onclick({
    target: { closest: () => ({ dataset: { removeGroup: "0" } }) },
  });
  h.state.groupDraft = ["Replacement"];
  h.state.groupSources = ["Replacement"];
  pending.resolve(true); await removing;
  assert.deepEqual(Array.from(h.state.groupDraft), ["Replacement"]);
  assert.deepEqual(Array.from(h.state.groupSources), ["Replacement"]);
});

test("committed group names survive refresh failure and are used by the next rename", async () => {
  const h = fixture(), requests = [];
  h.state.groupDraft = ["B", "Keep"];
  h.state.groupOriginal = ["A", "Keep", "Removed"];
  h.state.groupSources = ["A", "Keep"];
  h.state.profiles = [
    { id: "renamed", group: "A" }, { id: "kept", group: "Keep" },
    { id: "removed", group: "Removed", archived: true },
  ];
  let stored = JSON.parse(JSON.stringify(h.state.profiles));
  h.context.api = async (action, payload) => {
    assert.equal(action, "groups_save");
    requests.push(JSON.parse(JSON.stringify(payload)));
    stored = stored.map((profile) => {
      const next = payload.renames[profile.group] ?? profile.group;
      return { ...profile, group: payload.groups.includes(next) ? next : "" };
    });
    return { groups: payload.groups };
  };
  h.context.refreshProfiles = async () => { throw new Error("Fixture refresh failure"); };
  await h.context.saveGroups();
  assert.deepEqual(Array.from(h.state.groupSources), ["B", "Keep"]);
  assert.deepEqual(Array.from(h.state.groupOriginal), ["B", "Keep"]);
  assert.deepEqual(h.state.profiles.map((profile) => profile.group), ["B", "Keep", ""]);
  assert.equal(h.toasts.at(-1).type, "success");
  assert.match(h.serviceErrors.at(-1), /分组已保存.*列表刷新失败/);
  h.state.groupDraft[0] = "C";
  await h.context.saveGroups();
  assert.deepEqual(requests[1].renames, { B: "C" });
  assert.equal(stored[0].group, "C");
  assert.equal(h.state.profiles[0].group, "C");
  assert.equal(h.state.groupsSaving, false);
});

test("group commit accepts the service's normalized names and membership rules", async () => {
  const h = fixture(), requested = "Z".repeat(101), normalized = requested.slice(0, 100);
  h.state.groupDraft = [requested];
  h.state.groupSources = ["A"];
  h.state.groupOriginal = ["A"];
  h.state.profiles = [{ id: "fixture", group: "A" }];
  h.context.api = async () => ({ groups: [normalized] });
  h.context.refreshProfiles = async () => { throw new Error("Fixture refresh failure"); };
  await h.context.saveGroups();
  assert.deepEqual(Array.from(h.state.groups), [normalized]);
  assert.deepEqual(Array.from(h.state.groupDraft), [normalized]);
  assert.deepEqual(Array.from(h.state.groupSources), [normalized]);
  assert.equal(h.state.profiles[0].group, "");
});

test("collecting a draft preserves disabled fingerprint values", () => {
  const h = fixture();
  h.state.draft = { fingerprint: { canvasValue: 123 }, remark: "old" };
  h.element("#profile-form").all.set("[data-field]", [
    { disabled: true, dataset: { field: "fingerprint.canvasValue", type: "nullableNumber" }, value: "999" },
    { disabled: false, dataset: { field: "remark", type: "string" }, value: "new" },
  ]);
  const collected = h.context.collectDraft();
  assert.equal(collected.fingerprint.canvasValue, 123);
  assert.equal(collected.remark, "new");
  assert.equal(h.state.dirty, false);
});

test("independent guidance includes complete new local sources and keeps per-source checks", () => {
  const h = fixture();
  h.context.acceptBootstrap({ capabilities: { independent_runtime: true } });
  assert.match(h.element("#help-source-title").textContent, /本机完整窗口/);
  assert.match(h.element("#help-source-description").textContent, /新建窗口在比特中打开过.*正常关闭后.*参与来源检查/);
  assert.match(h.element("#help-import-notice").textContent, /完整配置、内核和浏览器资料通过检查/);
  assert.match(h.element("#help-import-notice").textContent, /缺失配置或资料.*逐项说明原因/);
  h.renderProfiles();
  assert.match(h.element("#empty-state p").textContent, /检查并导入比特本机完整窗口资料/);
  h.state.sync.loading = true;
  h.context.renderSync();
  assert.match(h.element("#sync-source-note").textContent, /无需启动原客户端、原厂授权或联网/);
  assert.match(h.element("#sync-explanation").textContent, /在比特中打开过的新窗口均会参与检查/);
  assert.match(h.element("#sync-preview-summary").textContent, /正在检查本机来源配置及完整资料/);
  h.state.sync.loading = false;
  h.context.renderSyncPreview();
  assert.match(h.element("#sync-empty").textContent, /新窗口请先在比特中打开.*正常关闭/);
  h.state.sync.preview = [
    { source_key: "fixture.missing", status: "missing_data" },
    { source_key: "fixture.open", status: "source_open" },
  ];
  h.context.renderSyncPreview();
  const rows = h.element("#sync-preview-rows").innerHTML;
  assert.match(rows, /缺少完整的本地配置或浏览器资料/);
  assert.match(rows, /正常关闭来源窗口.*完整配置和浏览器资料仍须通过检查/);
  assert.doesNotMatch(rows, /请在比特中确认资料完整落地/);
  h.state.sync.preview[0].reason = "Fixture reason <checked>";
  h.context.renderSyncPreview();
  assert.match(h.element("#sync-preview-rows").innerHTML, /Fixture reason &lt;checked&gt;/);
});

test("compatibility mode restores its source guidance and authorization boundary", () => {
  const h = fixture();
  h.context.acceptBootstrap({ capabilities: { independent_runtime: true } });
  h.context.acceptBootstrap({ capabilities: { independent_runtime: false } });
  assert.equal(h.element("#help-source-title").textContent, "从比特同步窗口");
  assert.match(h.element("#help-source-description").textContent, /联网及有效授权/);
  h.renderProfiles();
  assert.match(h.element("#empty-state p").textContent, /从比特复制本机已有完整资料/);
  h.state.sync.loading = true;
  h.context.renderSync();
  assert.match(h.element("#sync-source-note").textContent, /读取完整配置和签名仍需联网及有效授权/);
  assert.equal(h.element("#sync-preview-summary").textContent, "正在读取比特本机窗口资料…");
  h.state.sync.loading = false;
  h.context.renderSyncPreview();
  assert.match(h.element("#sync-empty").textContent, /请先在比特准备好窗口并正常关闭/);
  h.state.sync.preview = [{ source_key: "fixture.missing", status: "missing_data" }];
  h.context.renderSyncPreview();
  assert.match(h.element("#sync-preview-rows").innerHTML, /请在比特中确认资料完整落地后再试/);
});

function syncStatus(overrides = {}) {
  return {
    job_id: "fixture-job", state: "running", phase: "copying", total: 10000,
    current: 1, completed: 0, skipped: 0, failed: 0, items: [], items_total: 0,
    cancel_requested: false, ...overrides,
  };
}

test("10k candidates keep all rows available and cap each cross-page batch at 9999", async () => {
  const h = fixture();
  const candidates = Array.from({ length: 10000 }, (_, i) => ({
    source_key: `fixture-${i}`, name: `Window ${i}`, seq: i + 1,
    status: "ready", has_local_data: true,
  }));
  h.context.api = async () => ({ items: [...candidates, candidates[0], null] });
  await h.context.loadSyncPreview();
  assert.equal(h.state.sync.preview.length, 10000);
  assert.equal(h.state.sync.selected.size, 9999);
  assert.equal(h.state.sync.selected.has("fixture-9999"), false);
  assert.match(h.element("#sync-preview-summary").textContent, /候选 10000 个.*可导入 10000 个.*每批最多 9999/);
  assert.match(h.element("#sync-selection-count").textContent, /本批已选 9999.*本批未选 1 个.*下批/);
  h.state.sync.page = 200;
  h.context.renderSyncPreview();
  const rows = h.element("#sync-preview-rows").innerHTML;
  assert.equal((rows.match(/<tr>/g) || []).length, 50);
  assert.match(rows, /data-sync-index="9950"/);
  assert.match(rows, /data-sync-index="9999"/);
  const extra = { dataset: { syncIndex: "9999" }, checked: true };
  h.element("#sync-preview-rows").onchange({ target: { closest: () => extra } });
  assert.equal(extra.checked, false);
  assert.equal(h.state.sync.selected.size, 9999);
  assert.equal(h.state.sync.selected.has("fixture-9999"), false);
  assert.match(h.element("#sync-error").textContent, /最多同步 9999.*取消其他选择/);
  h.element("#sync-preview-rows").onchange({
    target: { closest: () => ({ dataset: { syncIndex: "9950" }, checked: false }) },
  });
  assert.equal(h.state.sync.selected.size, 9998);
  extra.checked = true;
  h.element("#sync-preview-rows").onchange({ target: { closest: () => extra } });
  h.element("#sync-search").oninput({ target: { value: "Window 1" } });
  assert.equal(h.state.sync.selected.size, 9999);
  const pending = deferred(), requests = [];
  h.context.api = async (action, payload) => {
    requests.push({ action, payload });
    if (action === "sync_windows") return pending.promise;
    return syncStatus({ state: "completed", completed: 9999, total: 9999 });
  };
  const first = h.context.startSync();
  await h.context.startSync();
  assert.equal(requests.length, 1);
  const keys = requests[0].payload.source_keys;
  assert.equal(keys.length, 9999);
  assert.equal(new Set(keys).size, 9999);
  assert.equal(keys.includes("fixture-9950"), false);
  assert.equal(keys.includes("fixture-0"), true);
  assert.equal(keys.includes("fixture-9999"), true);
  pending.resolve({ job_id: "fixture-job" });
  await first;
  await new Promise(setImmediate);
  assert.equal(h.state.sync.status.state, "completed");
  assert.equal(h.timers.size, 0);
  assert.match(h.element("#sync-background-note").textContent, /本批未选 1 个来源.*下批同步/);
  const imported = new Set(keys);
  h.context.api = async () => ({ items: candidates.map((item) => ({
    ...item, status: imported.has(item.source_key) ? "already_imported" : "ready",
  })) });
  await h.context.loadSyncPreview();
  assert.equal(h.state.sync.preview.length, 10000);
  assert.equal(h.state.sync.selected.size, 1);
  assert.equal(h.state.sync.selected.has("fixture-9950"), true);
  assert.match(h.element("#sync-preview-summary").textContent, /可导入 1 个.*已导入 9999 个/);
});

test("manual select all stays within 9999 and final start rejects an oversized selection", async () => {
  const h = fixture();
  h.state.sync.preview = Array.from({ length: 10000 }, (_, i) => ({
    source_key: `fixture-${i}`, name: `Window ${i}`, status: "ready", has_local_data: true,
  }));
  h.element("#sync-select-all").onchange({ target: { checked: true } });
  assert.equal(h.state.sync.preview.length, 10000);
  assert.equal(h.state.sync.selected.size, 9999);
  assert.equal(h.state.sync.selected.has("fixture-0"), true);
  assert.equal(h.state.sync.selected.has("fixture-9999"), false);
  assert.match(h.element("#sync-error").textContent, /本批前 9999 个.*其余来源留待下批/);
  assert.equal(h.element("#sync-select-all").checked, true);
  assert.equal(h.element("#sync-select-all").indeterminate, false);
  assert.match(h.element("#sync-select-all")["aria-label"], /本批最多 9999/);
  h.state.sync.selected.add("fixture-9999");
  let calls = 0;
  h.context.api = async () => { calls++; return { job_id: "fixture-job" }; };
  await h.context.startSync();
  assert.equal(calls, 0);
  assert.equal(h.state.sync.jobId, null);
  assert.match(h.element("#sync-error").textContent, /最多同步 9999.*减少本批选择/);
  h.element("#sync-select-all").onchange({ target: { checked: false } });
  assert.equal(h.state.sync.selected.size, 0);
});

test("10k status updates use bounded ID reads and preserve selected rows and drafts", async () => {
  const h = fixture();
  let idReads = 0;
  h.state.profiles = Array.from({ length: 10000 }, (_, i) => ({
    get id() { idReads++; return `fixture-${i}`; }, status: "closed", is_running: false,
  }));
  h.state.selected.add("fixture-5000");
  const draft = { id: "fixture-5000", remark: "unsaved" };
  const settingsDraft = { start_page: "https://fixture.invalid" };
  h.state.draft = draft;
  h.state.dirty = true;
  h.state.settingsDraft = settingsDraft;
  h.state.settingsDirty = true;
  h.context.api = async () => ({ profiles: Array.from({ length: 10000 }, (_, i) => ({
    id: `fixture-${i}`, status: "open", is_running: true,
  })) });
  await h.context.refreshStatus();
  assert.equal(h.state.profiles.every((p) => p.status === "open" && p.is_running), true);
  assert.ok(idReads <= 20000, `ID reads must remain proportional to row count: ${idReads}`);
  assert.equal(h.state.selected.has("fixture-5000"), true);
  assert.equal(h.state.draft, draft);
  assert.equal(h.state.dirty, true);
  assert.equal(h.state.settingsDraft, settingsDraft);
  assert.equal(h.state.settingsDirty, true);
});

test("bootstrap restores an active task with bounded results and keeps form drafts", async () => {
  const h = fixture();
  const draft = { id: "fixture", remark: "unsaved" };
  const settingsDraft = { start_page: "https://fixture.invalid" };
  h.state.draft = draft;
  h.state.dirty = true;
  h.state.settingsDraft = settingsDraft;
  h.state.settingsDirty = true;
  const items = Array.from({ length: 10000 }, (_, i) => ({
    source_key: `fixture-${i}`, name: `Result ${i}`, status: "completed",
  }));
  h.context.acceptBootstrap({
    settings: { start_page: "https://saved.fixture.invalid" },
    sync_job: syncStatus({ completed: 10000, items, items_total: 10000 }),
  });
  assert.equal(h.state.sync.jobId, "fixture-job");
  assert.equal(h.context.syncRunning(), true);
  assert.equal(h.state.sync.status.items.length, 100);
  assert.equal(h.state.sync.status.items[0].name, "Result 9900");
  assert.equal((h.element("#sync-result-list").innerHTML.match(/class="sync-result-item"/g) || []).length, 100);
  assert.match(h.element("#sync-result-list").innerHTML, /Result 9999/);
  assert.match(h.element("#sync-result-list").innerHTML, /显示最近 100 项/);
  assert.equal(h.timers.size, 1);
  assert.equal(h.state.draft, draft);
  assert.equal(h.state.dirty, true);
  assert.equal(h.state.settingsDraft, settingsDraft);
  assert.equal(h.state.settingsDirty, true);
  h.context.api = async () => syncStatus({ state: "completed", completed: 10000, items: items.slice(-100), items_total: 10000 });
  await h.context.pollSyncStatus();
  assert.equal(h.timers.size, 0);
  assert.equal(h.state.sync.status.items.length, 100);
  assert.match(h.element("#sync-progress-summary").textContent, /成功 10000 个/);
  assert.equal(h.toasts.length, 1);
});

test("an interrupted task waits for explicit resume and resumes the same job once", async () => {
  const h = fixture();
  h.context.acceptBootstrap({ sync_job: syncStatus({ state: "interrupted", completed: 125 }) });
  assert.equal(h.context.syncRunning(), false);
  assert.equal(h.timers.size, 0);
  assert.match(h.element("#sync-phase").textContent, /已中断/);
  assert.match(h.element("#sync-start").textContent, /继续剩余同步/);
  h.context.openSyncDialog({ autoStart: true });
  assert.equal(h.state.sync.jobId, "fixture-job");
  const pending = deferred(), calls = [];
  h.context.api = async (action, payload) => {
    calls.push({ action, payload });
    return action === "resume_sync" ? pending.promise : syncStatus({ completed: 126 });
  };
  const first = h.context.startSync();
  await h.context.startSync();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].action, "resume_sync");
  assert.equal(calls[0].payload.job_id, "fixture-job");
  pending.resolve({ job_id: "fixture-job" });
  await first;
  await new Promise(setImmediate);
  assert.equal(h.state.sync.status.completed, 126);
  assert.equal(h.context.syncRunning(), true);
  assert.equal(h.timers.size, 1);
});

for (const oldReply of ["interrupted", "error", "missing"]) {
  test(`same-job resume ignores an older ${oldReply} reply and repolls without overlap`, async () => {
    const h = fixture();
    h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 125 }));
    const old = deferred();
    let statusCalls = 0, inFlight = 0, peak = 0;
    h.context.api = async (action) => {
      if (action === "resume_sync") return { job_id: "fixture-job" };
      statusCalls++;
      inFlight++;
      peak = Math.max(peak, inFlight);
      try {
        return statusCalls === 1 ? await old.promise : syncStatus({ completed: 126 });
      } finally { inFlight--; }
    };
    const first = h.context.pollSyncStatus();
    await h.context.resumeSyncJob();
    assert.equal(h.context.syncRunning(), true);
    assert.equal(statusCalls, 1);
    if (oldReply === "error") old.reject(new Error("fixture stale failure"));
    else if (oldReply === "missing") old.resolve(null);
    else old.resolve(syncStatus({ state: "interrupted", completed: 125 }));
    await first;
    assert.equal(h.context.syncRunning(), true);
    assert.equal(h.state.sync.pollErrors, 0);
    assert.equal(h.state.sync.pollPaused, false);
    assert.equal(h.state.sync.error, "");
    assert.equal(h.timers.size, 1);
    const [timerId, timer] = [...h.timers][0];
    assert.equal(timer.delay, 0);
    h.timers.delete(timerId);
    await timer.callback();
    assert.equal(statusCalls, 2);
    assert.equal(peak, 1);
    assert.equal(h.state.sync.status.completed, 126);
    assert.equal(h.state.sync.status.state, "running");
    assert.equal(h.timers.size, 1);
    assert.equal([...h.timers.values()][0].delay, 1000);
  });
}

test("a stale status finishing during resume waits for the resume reply before polling again", async () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 125 }));
  const old = deferred(), resume = deferred();
  let statusCalls = 0;
  h.context.api = async (action) => {
    if (action === "resume_sync") return resume.promise;
    statusCalls++;
    return statusCalls === 1 ? old.promise : syncStatus({ completed: 126 });
  };
  const first = h.context.pollSyncStatus();
  const continuing = h.context.resumeSyncJob();
  old.resolve(syncStatus({ state: "interrupted", completed: 125 }));
  await first;
  assert.equal(statusCalls, 1);
  assert.equal(h.timers.size, 0);
  assert.equal(h.state.sync.starting, true);
  resume.resolve({ job_id: "fixture-job" });
  await continuing;
  await new Promise(setImmediate);
  assert.equal(statusCalls, 2);
  assert.equal(h.state.sync.status.state, "running");
  assert.equal(h.state.sync.status.completed, 126);
});

for (const oldReply of ["interrupted", "error"]) {
  test(`bootstrap reattachment ignores an older ${oldReply} status and refreshes its new state`, async () => {
    const h = fixture();
    h.context.restoreSyncJob(syncStatus({ completed: 125 }));
    const old = deferred();
    let statusCalls = 0;
    h.context.api = async () => {
      statusCalls++;
      return statusCalls === 1 ? old.promise : syncStatus({ completed: 127 });
    };
    const first = h.context.pollSyncStatus();
    h.context.acceptBootstrap({ sync_job: syncStatus({ completed: 126 }) });
    if (oldReply === "error") old.reject(new Error("fixture stale failure"));
    else old.resolve(syncStatus({ state: "interrupted", completed: 125 }));
    await first;
    assert.equal(h.state.sync.status.state, "running");
    assert.equal(h.state.sync.status.completed, 126);
    assert.equal(h.state.sync.pollErrors, 0);
    assert.equal(h.state.sync.pollPaused, false);
    const [timerId, timer] = [...h.timers][0];
    assert.equal(timer.delay, 0);
    h.timers.delete(timerId);
    await timer.callback();
    assert.equal(statusCalls, 2);
    assert.equal(h.state.sync.status.completed, 127);
  });
}

test("a bootstrap requested before same-job resume cannot restore its old interrupted snapshot", async () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 125 }));
  const snapshot = deferred();
  h.context.api = async (action) => {
    if (action === "bootstrap") return snapshot.promise;
    if (action === "resume_sync") return { job_id: "fixture-job" };
    return syncStatus({ completed: 126 });
  };
  const reconnecting = h.context.bootstrap({ quiet: true });
  await h.context.resumeSyncJob();
  await new Promise(setImmediate);
  snapshot.resolve({ sync_job: syncStatus({ state: "interrupted", completed: 125 }) });
  await reconnecting;
  assert.equal(h.state.sync.status.state, "running");
  assert.equal(h.state.sync.status.completed, 126);
  assert.equal(h.timers.size, 1);
});

for (const mutation of ["resume", "cancel"]) {
  for (const snapshotTiming of ["before", "after"]) {
    test(`bootstrap requested during ${mutation} and returned ${snapshotTiming} confirmation cannot roll back progress`, async () => {
      const h = fixture();
      const resuming = mutation === "resume";
      const initial = syncStatus({ state: resuming ? "interrupted" : "running", completed: 125 });
      h.context.restoreSyncJob(initial);
      const confirmation = deferred(), snapshot = deferred();
      let statusCalls = 0, inFlight = 0, peak = 0;
      h.context.api = async (action) => {
        if (action === "bootstrap") return snapshot.promise;
        if (action === (resuming ? "resume_sync" : "cancel_sync")) return confirmation.promise;
        statusCalls++;
        inFlight++;
        peak = Math.max(peak, inFlight);
        try { return syncStatus({ completed: 126, cancel_requested: !resuming }); }
        finally { inFlight--; }
      };
      const changing = resuming ? h.context.resumeSyncJob() : h.context.cancelSyncJob();
      const reconnecting = h.context.bootstrap({ quiet: true });
      if (snapshotTiming === "before") {
        snapshot.resolve({ sync_job: initial });
        await reconnecting;
        assert.equal(h.state.sync.status.state, initial.state);
        assert.equal(h.state.sync.status.completed, 125);
        assert.equal(resuming ? h.state.sync.starting : h.state.sync.cancelling, true);
        assert.equal(statusCalls, 0);
        assert.equal(h.timers.size, 0);
      }
      confirmation.resolve(resuming ? { job_id: "fixture-job" } : { requested: true });
      await changing;
      await new Promise(setImmediate);
      assert.equal(h.state.sync.status.state, "running");
      assert.equal(h.state.sync.status.completed, 126);
      assert.equal(h.state.sync.cancelRequested, !resuming);
      if (snapshotTiming === "after") {
        snapshot.resolve({ sync_job: initial });
        await reconnecting;
      }
      assert.equal(h.state.sync.status.state, "running");
      assert.equal(h.state.sync.status.completed, 126);
      assert.equal(h.state.sync.cancelRequested, !resuming);
      assert.equal(h.state.sync.pollPaused, false);
      assert.equal(h.state.sync.pollErrors, 0);
      assert.equal(statusCalls, 1);
      assert.equal(peak, 1);
      assert.equal(h.timers.size, 1);
      assert.equal([...h.timers.values()][0].delay, 1000);
    });
  }

  test(`a bootstrap requested during uncertain ${mutation} cannot clear its pause, and a later refresh can recover`, async () => {
    const h = fixture();
    const resuming = mutation === "resume";
    const initial = syncStatus({ state: resuming ? "interrupted" : "running", completed: 125 });
    h.context.restoreSyncJob(initial);
    const confirmation = deferred(), snapshot = deferred();
    h.context.api = async (action) => action === "bootstrap" ? snapshot.promise : confirmation.promise;
    const changing = resuming ? h.context.resumeSyncJob() : h.context.cancelSyncJob();
    const reconnecting = h.context.bootstrap({ quiet: true });
    confirmation.reject(new Error("fixture confirmation lost"));
    await changing;
    snapshot.resolve({ sync_job: initial });
    await reconnecting;
    assert.equal(h.state.sync.status.completed, 125);
    assert.equal(h.state.sync.pollPaused, true);
    assert.match(h.state.sync.error, /请求未确认/);
    assert.equal(h.timers.size, 0);
    h.context.api = async () => ({ sync_job: syncStatus({ completed: 126, cancel_requested: !resuming }) });
    await h.context.bootstrap({ quiet: true });
    assert.equal(h.state.sync.status.state, "running");
    assert.equal(h.state.sync.status.completed, 126);
    assert.equal(h.state.sync.cancelRequested, !resuming);
    assert.equal(h.state.sync.pollPaused, false);
    assert.equal(h.timers.size, 1);
  });
}

test("cancelled interrupted work stays cancelled when an older status response arrives", async () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 125, cancel_requested: true }));
  const pending = deferred();
  h.context.api = async (action) => action === "sync_status" ? pending.promise : { requested: true };
  const oldPoll = h.context.pollSyncStatus();
  await h.context.cancelSyncJob();
  assert.equal(h.state.sync.status.state, "cancelled");
  pending.resolve(syncStatus({ state: "interrupted", completed: 125 }));
  await oldPoll;
  assert.equal(h.state.sync.status.state, "cancelled");
  assert.equal(h.context.syncRunning(), false);
  assert.equal(h.timers.size, 0);
  assert.equal(h.element("#sync-cancel-job").hidden, true);
});

test("a confirmed cancellation ignores an older status error", async () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 125 }));
  const old = deferred();
  h.context.api = async (action) => action === "sync_status" ? old.promise : { requested: true };
  const first = h.context.pollSyncStatus();
  await h.context.cancelSyncJob();
  old.reject(new Error("fixture stale failure"));
  await first;
  assert.equal(h.state.sync.status.state, "cancelled");
  assert.equal(h.state.sync.pollErrors, 0);
  assert.equal(h.state.sync.pollPaused, false);
  assert.equal(h.state.sync.error, "");
  assert.equal(h.timers.size, 0);
});

test("status polling pauses after three failures and stops automatically on interrupted state", async () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus());
  h.context.api = async () => { throw new Error("fixture failure"); };
  for (let i = 0; i < 3; i++) await h.context.pollSyncStatus();
  assert.equal(h.state.sync.pollPaused, true);
  assert.equal(h.timers.size, 0);
  assert.equal(h.element("#sync-retry-status").hidden, false);
  h.context.api = async () => syncStatus({ state: "interrupted", completed: 25 });
  h.context.resumeSyncStatus();
  await new Promise(setImmediate);
  assert.equal(h.state.sync.status.state, "interrupted");
  assert.equal(h.context.syncRunning(), false);
  assert.equal(h.timers.size, 0);
  assert.equal(h.toasts.length, 0);
});

test("failed resume keeps interruption visible and permits reading uncertain progress", async () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 20 }));
  h.context.api = async () => { throw new Error("fixture lost reply"); };
  await h.context.startSync();
  assert.equal(h.state.sync.status.state, "interrupted");
  assert.equal(h.state.sync.status.completed, 20);
  assert.equal(h.state.sync.pollPaused, true);
  assert.equal(h.element("#sync-retry-status").hidden, false);
  assert.equal(h.timers.size, 0);
  h.context.api = async () => syncStatus({ completed: 21 });
  h.context.resumeSyncStatus();
  await new Promise(setImmediate);
  assert.equal(h.context.syncRunning(), true);
  assert.equal(h.state.sync.status.completed, 21);
  assert.equal(h.timers.size, 1);
});

test("an uncertain interrupted cancellation can read its confirmed terminal state", async () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 20 }));
  h.context.api = async () => { throw new Error("fixture lost cancellation reply"); };
  await h.context.cancelSyncJob();
  assert.equal(h.state.sync.status.state, "interrupted");
  assert.equal(h.state.sync.pollPaused, true);
  assert.equal(h.element("#sync-retry-status").hidden, false);
  h.context.api = async () => syncStatus({ state: "cancelled", completed: 20, cancel_requested: true });
  h.context.resumeSyncStatus();
  await new Promise(setImmediate);
  assert.equal(h.state.sync.status.state, "cancelled");
  assert.equal(h.timers.size, 0);
});

test("confirmed manual refresh still replaces the settings draft", () => {
  const h = fixture();
  h.state.settingsDraft = { start_page: "https://unsaved.fixture.invalid" };
  h.state.settingsDirty = true;
  h.context.acceptBootstrap({ settings: { start_page: "https://saved.fixture.invalid" } }, { preserveDrafts: false });
  assert.equal(h.state.settingsDraft.start_page, "https://saved.fixture.invalid");
  assert.equal(h.state.settingsDirty, false);
});

test("static DOM references exist and obsolete public controls are absent", () => {
  const html = fs.readFileSync(path.join(root, "app/ui/index.html"), "utf8");
  const htmlIds = Array.from(html.matchAll(/\bid="([^"]+)"/g), (match) => match[1]);
  assert.equal(new Set(htmlIds).size, htmlIds.length);
  const ids = new Set([
    ...htmlIds, ...Array.from(source.matchAll(/\bid="([A-Za-z][\w-]*)"/g), (match) => match[1]),
  ]);
  for (const match of source.matchAll(/\b(field|fp)\(\s*["']([\w.]+)["']/g)) {
    ids.add("field-" + ((match[1] === "fp" ? "fingerprint." : "") + match[2]).replaceAll(".", "-"));
  }
  const refs = Array.from(source.matchAll(/\$\(\s*["']#([A-Za-z][\w-]*)["']\s*(?=[,)])/g), (match) => match[1]);
  assert.deepEqual(refs.filter((id) => !ids.has(id)), []);
  assert.doesNotMatch(html, /id="(?:import-button|randomize-button|count-created)"|data-batch="duplicate"/);
  assert.doesNotMatch(source, /api\("randomize"|transferProfiles|\$\("#(?:import-button|randomize-button|count-created)"/);
});

function deletionFixture(count = 1, recycle = false) {
  const h = fixture();
  h.state.panel = recycle ? "recycle" : "profiles";
  h.state.profiles = Array.from({ length: count }, (_, i) => ({
    id: `fixture-${i}`, name: `Fixture ${i}`, archived: recycle,
  }));
  const selection = recycle ? h.state.recycleSelected : h.state.selected;
  h.state.profiles.forEach((profile) => selection.add(profile.id));
  h.previewRefreshes = 0;
  h.loadSyncPreview = h.context.loadSyncPreview;
  h.context.loadSyncPreview = async () => { h.previewRefreshes++; };
  h.context.api = async (action, payload) => action === "batch"
    ? { results: payload.ids.map((id) => ({ id, ok: true, data: { deleted: true, cleanup_complete: true } })) }
    : { deleted: true, cleanup_complete: true };
  return h;
}

test("delete confirmation explains scope, defaults to cancel, and sends no API after cancellation", async () => {
  const h = deletionFixture(); let calls = 0;
  h.context.api = async () => { calls++; };
  h.context.confirmAction = async (title, message, accept) => {
    assert.equal(h.state.deleteBusy, true);
    assert.equal(h.state.operationActions.get("fixture-0"), "delete");
    assert.match(title, /彻底删除/);
    assert.match(message, /无法恢复/);
    assert.match(message, /正常关闭所选的本地浏览器窗口/);
    assert.match(message, /配置、浏览器资料和可识别的恢复副本/);
    assert.match(message, /共用内核、原比特来源、手动导出及外部备份不删除/);
    assert.match(message, /日后同步仍可重新导入/);
    assert.equal(accept, "彻底删除");
    return false;
  };
  await h.context.performAction("delete", "fixture-0");
  await h.context.batchAction("delete", h.element("batch"));
  assert.equal(calls, 0);
  assert.equal(h.state.profiles.length, 1);
  assert.equal(h.state.deleteBusy, false);
  assert.equal(h.state.batchBusy, false);
  assert.equal(h.state.operationIds.size, 0);
  let cancelFocused = false;
  h.element("#confirm-cancel").focus = () => { cancelFocused = true; };
  const confirmation = h.nativeConfirmAction("Fixture", "Fixture", "彻底删除");
  const dialog = h.element("#confirm-dialog");
  assert.equal(dialog.returnValue, "cancel");
  assert.equal(cancelFocused, true);
  dialog.listeners.get("close")();
  assert.equal(await confirmation, false);
});

test("single delete uses its ID contract and clears only that profile's draft and cached state", async () => {
  const h = deletionFixture(2), calls = [];
  const untouched = h.state.profiles[1];
  h.state.draft = { id: "fixture-0", cookie_text: "fixture draft" };
  h.state.dirty = true;
  h.state.sync.preview = [{ source_key: "fixture-source", status: "already_imported" }];
  h.state.sync.names.set("fixture-source", "Fixture");
  h.state.sync.selected.add("fixture-source");
  h.element("#profile-form").innerHTML = "fixture old form";
  h.context.api = async (action, payload) => {
    calls.push({ action, payload: JSON.parse(JSON.stringify(payload)) });
    return { deleted: true, cleanup_complete: true };
  };
  await h.context.performAction("delete", "fixture-0");
  assert.deepEqual(calls, [{ action: "delete", payload: { id: "fixture-0" } }]);
  assert.deepEqual(Array.from(h.state.selected), ["fixture-1"]);
  assert.equal(h.state.profiles.length, 1);
  assert.equal(h.state.profiles[0], untouched);
  assert.equal(h.state.draft, null);
  assert.equal(h.state.dirty, false);
  assert.equal(h.element("#profile-form").innerHTML, "");
  assert.equal(h.element("#profile-drawer").hidden, true);
  assert.equal(h.state.sync.preview.length, 0);
  assert.equal(h.state.sync.names.size, 0);
  assert.equal(h.state.sync.selected.size, 0);
  assert.equal(h.previewRefreshes, 1);
  assert.equal(h.toasts.at(-1).type, "success");
});

test("delete reserves IDs during confirmation and rejects repeated clicks through the request", async () => {
  const h = deletionFixture(), confirmation = deferred(), request = deferred();
  let confirmed = 0, calls = 0;
  h.context.confirmAction = async () => { confirmed++; return confirmation.promise; };
  h.context.api = async () => { calls++; return request.promise; };
  const first = h.context.performAction("delete", "fixture-0");
  await h.context.performAction("delete", "fixture-0");
  await h.context.batchAction("delete", h.element("batch"));
  assert.equal(confirmed, 1);
  assert.equal(calls, 0);
  confirmation.resolve(true); await Promise.resolve(); await Promise.resolve();
  await h.context.performAction("delete", "fixture-0");
  assert.equal(calls, 1);
  request.resolve({ deleted: true, cleanup_complete: true }); await first;
  assert.equal(h.state.deleteBusy, false);
  assert.equal(h.state.operationIds.size, 0);
});

for (const change of ["identity", "archived", "selection", "selection object", "panel"]) {
  test(`late delete confirmation aborts when ${change} changes`, async () => {
    const h = deletionFixture(2), confirmation = deferred(); let calls = 0;
    h.context.confirmAction = async () => confirmation.promise;
    h.context.api = async () => { calls++; };
    const action = h.context.batchAction("delete", h.element("batch"));
    if (change === "identity") h.state.profiles[0] = { ...h.state.profiles[0] };
    if (change === "archived") h.state.profiles[0].archived = true;
    if (change === "selection") h.state.selected.delete("fixture-1");
    if (change === "selection object") h.state.selected = new Set(["fixture-0", "fixture-1"]);
    if (change === "panel") h.state.panel = "recycle";
    confirmation.resolve(true); await action;
    assert.equal(calls, 0);
    assert.equal(h.state.deletedIds.size, 0);
    assert.match(h.toasts.at(-1).message, /未执行删除/);
    assert.equal(h.state.batchBusy, false);
  });
}

test("205 deletions use sequential 100-ID batch segments with exact per-ID confirmation", async () => {
  const h = deletionFixture(205), sizes = []; let active = 0, maximum = 0;
  h.context.api = async (action, payload) => {
    assert.equal(action, "batch"); assert.equal(payload.action, "delete");
    assert.equal(h.state.batchBusy, true);
    active++; maximum = Math.max(maximum, active);
    sizes.push(payload.ids.length); await Promise.resolve(); active--;
    return { completed: payload.ids.length, errors: [], results: payload.ids.map((id) => ({ id, ok: true, data: { deleted: true, cleanup_complete: true } })) };
  };
  await h.context.batchAction("delete", h.element("batch"));
  assert.deepEqual(sizes, [100, 100, 5]);
  assert.equal(maximum, 1);
  assert.equal(h.state.deletedIds.size, 205);
  assert.equal(h.state.selected.size, 0);
  assert.equal(h.state.profiles.length, 0);
  assert.equal(h.previewRefreshes, 1);
  assert.match(h.toasts.at(-1).message, /已彻底删除 205 个/);
});

test("partial deletion clears retired state but never counts unfinished cleanup or unknown results as success", async () => {
  const h = deletionFixture(4);
  h.state.draft = { id: "fixture-1" };
  h.context.api = async () => ({ completed: 4, errors: [], results: [
    { id: "fixture-0", ok: true, data: { deleted: true, cleanup_complete: true } },
    { id: "fixture-1", ok: true, data: { deleted: true, cleanup_complete: false } },
    { id: "fixture-2", ok: false, error: "Fixture refusal" },
    { id: "unselected-fixture", ok: true, data: { deleted: true, cleanup_complete: true } },
  ] });
  await h.context.batchAction("delete", h.element("batch"));
  assert.equal(h.state.draft, null);
  assert.deepEqual(Array.from(h.state.deletedIds), ["fixture-0", "fixture-1"]);
  assert.deepEqual(Array.from(h.state.selected), ["fixture-2", "fixture-3"]);
  assert.equal(h.toasts.at(-1).type, "error");
  assert.match(h.toasts.at(-1).message, /已彻底删除 1 个.*未完成 3 个/);
  assert.match(h.toasts.at(-1).message, /删除后的存储清理未完成/);
  assert.match(h.toasts.at(-1).message, /重启程序继续清理/);
});

test("aggregate completed counts and duplicate IDs cannot stand in for complete deletion results", async () => {
  for (const results of [undefined, [
    { id: "fixture-0", ok: true, data: { deleted: true, cleanup_complete: true } },
    { id: "fixture-0", ok: true, data: { deleted: true, cleanup_complete: true } },
  ]]) {
    const h = deletionFixture();
    h.context.api = async () => ({ completed: 1, errors: [], results });
    await h.context.batchAction("delete", h.element("batch"));
    assert.equal(h.state.deletedIds.size, 0);
    assert.equal(h.toasts.at(-1).type, "error");
    assert.match(h.toasts.at(-1).message, /已彻底删除 0 个/);
  }
});

test("interrupted deletion reports unconfirmed remainder and retains failures without claiming preserved data", async () => {
  const h = deletionFixture(205); let calls = 0;
  h.context.api = async (action, payload) => {
    if (++calls === 2) throw new Error("Fixture lost reply");
    return { results: payload.ids.map((id) => ({ id, ok: true, data: { deleted: true, cleanup_complete: true } })) };
  };
  await h.context.batchAction("delete", h.element("batch"));
  assert.equal(calls, 2);
  assert.equal(h.state.selected.size, 105);
  assert.match(h.toasts.at(-1).message, /已确认彻底删除 100 个.*105 个结果未确认/);
  assert.doesNotMatch(h.toasts.at(-1).message, /资料.*保留/);
  assert.equal(h.state.batchBusy, false);
});

test("deletion remains confirmed when list or source refresh fails, and all busy flags release", async () => {
  const h = deletionFixture();
  h.context.refreshProfiles = async () => { throw new Error("Fixture refresh failed"); };
  h.context.loadSyncPreview = async () => { throw new Error("Fixture preview failed"); };
  await h.context.performAction("delete", "fixture-0");
  assert.equal(h.toasts.length, 1);
  assert.equal(h.toasts[0].type, "success");
  assert.ok(h.serviceErrors.some((message) => /列表刷新失败/.test(message)));
  assert.ok(h.serviceErrors.some((message) => /来源预览刷新失败/.test(message)));
  assert.equal(h.state.profiles.length, 0);
  assert.equal(h.state.deleteBusy, false);
  assert.equal(h.state.operationIds.size, 0);
});

test("late list and bootstrap responses cannot resurrect a deleted profile", async () => {
  const h = deletionFixture(2), staleList = deferred();
  const original = h.state.profiles.slice();
  h.context.api = async (action) => action === "list" ? staleList.promise : { deleted: true, cleanup_complete: true };
  const refresh = h.refreshProfiles();
  await h.context.performAction("delete", "fixture-0");
  staleList.resolve({ profiles: original }); await refresh;
  assert.deepEqual(Array.from(h.state.profiles, (profile) => profile.id), ["fixture-1"]);
  h.context.acceptBootstrap({ profiles: original });
  assert.deepEqual(Array.from(h.state.profiles, (profile) => profile.id), ["fixture-1"]);
  assert.equal(h.state.selected.has("fixture-0"), false);
});

test("late list replies cannot overwrite a newer profile list or groups", async () => {
  const h = fixture(), stale = deferred();
  let calls = 0;
  h.context.api = async () => ++calls === 1 ? stale.promise : {
    profiles: [{ id: "fixture", name: "new", archived: true }], groups: ["new"],
  };
  const first = h.refreshProfiles();
  await h.refreshProfiles();
  stale.resolve({ profiles: [{ id: "fixture", name: "old", archived: false }], groups: ["old"] });
  await first;
  assert.equal(h.state.profiles[0].name, "new");
  assert.equal(h.state.profiles[0].archived, true);
  assert.deepEqual(Array.from(h.state.groups), ["new"]);
});

test("bootstrap requested before a list refresh cannot restore stale metadata", async () => {
  const h = fixture(), stale = deferred();
  let connected = false;
  h.context.setConnection = (value) => { connected = value; };
  h.context.api = async (action) => action === "bootstrap" ? stale.promise : {
    profiles: [{ id: "fixture", name: "saved" }], groups: ["saved"],
  };
  const bootstrap = h.context.bootstrap({ quiet: true });
  await h.refreshProfiles();
  stale.resolve({ profiles: [{ id: "fixture", name: "old" }], groups: ["old"],
    cores: ["148"], capabilities: { sync_windows: true }, settings: { confirm_close: true },
    sync_job: { job_id: "fixture-job", state: "interrupted" } });
  await bootstrap;
  assert.equal(h.state.profiles[0].name, "saved");
  assert.deepEqual(Array.from(h.state.groups), ["saved"]);
  assert.equal(h.state.loading, false);
  assert.equal(connected, true);
  assert.equal(h.state.capabilities.sync_windows, true);
  assert.deepEqual(Array.from(h.state.cores), ["148"]);
  assert.equal(h.state.settingsLoaded, true);
  assert.equal(h.state.sync.jobId, "fixture-job");
  assert.equal(h.state.sync.status.state, "interrupted");
});

test("stale bootstrap cannot undo settings saved while its list was superseded", async () => {
  const h = fixture(), stale = deferred();
  h.context.api = async (action) => action === "bootstrap" ? stale.promise : { profiles: [] };
  const bootstrap = h.context.bootstrap({ quiet: true });
  h.state.settingsLoaded = true;
  h.state.settingsRevision++;
  h.state.settings = { confirm_close: false };
  h.state.settingsDraft = { confirm_close: false };
  await h.refreshProfiles();
  stale.resolve({ profiles: [], settings: { confirm_close: true } });
  await bootstrap;
  assert.equal(h.state.settings.confirm_close, false);
  assert.equal(h.state.settingsDraft.confirm_close, false);
});

for (const read of ["bootstrap", "loadSettings"]) {
  test(`late ${read} cannot overwrite a newer confirmed settings save`, async () => {
    const h = fixture(), stale = deferred();
    h.state.settings = { confirm_close: true };
    h.state.settingsDraft = { confirm_close: false };
    h.state.settingsDirty = true;
    h.context.api = async (action, payload) => action === "settings_save"
      ? { settings: payload.settings } : stale.promise;
    const reading = h.context[read]({ quiet: true });
    await h.context.saveSettings();
    stale.resolve({ profiles: [], settings: { confirm_close: true } });
    await reading;
    assert.equal(h.state.settings.confirm_close, false);
    assert.equal(h.state.settingsDraft.confirm_close, false);
    assert.equal(h.state.settingsLoaded, true);
  });
}

test("initial bootstrap and settings read still render the settings panel", async () => {
  const h = fixture(), bootstrapReply = deferred(), settingsReply = deferred();
  let rendered = 0;
  h.state.panel = "settings";
  h.context.renderSettings = () => { rendered++; };
  h.context.api = async (action) => action === "bootstrap" ? bootstrapReply.promise : settingsReply.promise;
  const bootstrap = h.context.bootstrap({ quiet: true });
  const settings = h.context.loadSettings();
  bootstrapReply.resolve({ profiles: [], settings: { confirm_close: true } });
  await bootstrap;
  settingsReply.resolve({ confirm_close: true });
  await settings;
  assert.equal(rendered, 1);
  assert.equal(h.state.settingsLoaded, true);
});

test("bridge fallback settings read cannot overwrite a confirmed save", async () => {
  const h = fixture(), stale = deferred();
  let readStarted = false;
  h.context.apiAvailable = () => true;
  h.context.bootstrap = async () => {};
  h.context.api = async (action, payload) => {
    if (action === "settings_save") return { settings: payload.settings };
    readStarted = true;
    return stale.promise;
  };
  h.context.initializeBridge();
  await Promise.resolve();
  assert.equal(readStarted, true);
  h.state.settingsDraft = { confirm_close: false };
  await h.context.saveSettings();
  stale.resolve({ confirm_close: true });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.state.settings.confirm_close, false);
  assert.equal(h.state.settingsLoaded, true);
});

test("source preview requested before deletion cannot overwrite the refreshed preview", async () => {
  const h = deletionFixture(), oldPreview = deferred(); let previews = 0;
  h.context.loadSyncPreview = h.loadSyncPreview;
  h.context.api = async (action) => {
    if (action === "sync_preview") return ++previews === 1 ? oldPreview.promise : { items: [{ source_key: "new-fixture", name: "New fixture", status: "ready" }] };
    return { deleted: true, cleanup_complete: true };
  };
  const old = h.context.loadSyncPreview();
  await h.context.performAction("delete", "fixture-0");
  assert.equal(previews, 2);
  oldPreview.resolve({ items: [{ source_key: "old-fixture", name: "Old fixture", status: "already_imported" }] }); await old;
  assert.equal(h.state.sync.preview[0].source_key, "new-fixture");
  assert.equal(h.state.sync.names.has("old-fixture"), false);
  assert.deepEqual(Array.from(h.state.sync.selected), ["new-fixture"]);
  assert.equal(h.state.sync.loading, false);
});

test("recycle selection is isolated and its bulk delete sends archived IDs only", async () => {
  const h = deletionFixture(2, true), sent = [];
  h.state.profiles.push({ id: "active-fixture", name: "Active fixture" });
  h.state.selected.add("active-fixture");
  h.state.recycleSelected.clear();
  h.element("#recycle-select-all").onchange({ target: { checked: true } });
  assert.deepEqual(Array.from(h.state.recycleSelected), ["fixture-0", "fixture-1"]);
  assert.deepEqual(Array.from(h.state.selected), ["active-fixture"]);
  h.element("#recycle-list").listeners.get("change")({ target: {
    matches: () => true, dataset: { recycleSelect: "active-fixture" }, checked: true,
  } });
  assert.equal(h.state.recycleSelected.has("active-fixture"), false);
  h.context.api = async (action, payload) => {
    assert.equal(action, "batch"); assert.equal(payload.action, "delete");
    sent.push(...payload.ids);
    return { results: payload.ids.map((id) => ({ id, ok: true, data: { deleted: true, cleanup_complete: true } })) };
  };
  await h.element("#recycle-delete-selected").onclick();
  assert.deepEqual(sent, ["fixture-0", "fixture-1"]);
  assert.deepEqual(Array.from(h.state.selected), ["active-fixture"]);
  assert.equal(h.state.recycleSelected.size, 0);
  h.state.recycleSelected.add("active-fixture");
  await h.context.batchAction("delete", h.element("batch"), { recycle: true });
  assert.equal(sent.length, 2);
});

test("delete controls are adjacent to archive controls and escape profile values", () => {
  const html = fs.readFileSync(path.join(root, "app/ui/index.html"), "utf8");
  assert.match(html, /data-batch="archive"[^>]*>[\s\S]*?<\/button\s*><button data-batch="delete"/);
  assert.match(html, /id="confirm-cancel"[^>]*autofocus/);
  const h = deletionFixture(1, true);
  h.state.profiles[0].id = 'fixture"><img src=x onerror=fixture>';
  h.state.profiles[0].name = '<img src=x onerror="fixture">';
  h.context.renderRecycle();
  const rendered = h.element("#recycle-list").innerHTML;
  assert.doesNotMatch(rendered, /<img/);
  assert.match(rendered, /&lt;img/);
  assert.match(rendered, /data-restore=/); assert.match(rendered, /data-delete=/);
  h.context.innerWidth = 1280; h.context.innerHeight = 720;
  h.context.openRowMenu(h.state.profiles[0].id, { getBoundingClientRect: () => ({ right: 500, top: 50, bottom: 80 }) });
  const menu = h.element("#row-menu").innerHTML;
  assert.match(menu, /data-menu-action="archive"[\s\S]*?<\/button><button class="danger-text" data-menu-action="delete"/);
  assert.doesNotMatch(menu, /<img/);
});

test("archive remains recoverable and restore retains its original action contract", async () => {
  const h = deletionFixture(), actions = [];
  h.context.confirmAction = async (title, message) => { assert.match(message, /资料会保留.*恢复/); return true; };
  h.context.api = async (action, payload) => { actions.push([action, payload.id]); return {}; };
  await h.context.performAction("archive", "fixture-0");
  h.state.profiles[0].archived = true;
  await h.context.performAction("restore", "fixture-0");
  assert.deepEqual(actions, [["archive", "fixture-0"], ["restore", "fixture-0"]]);
  assert.equal(h.state.deletedIds.size, 0);
});

test("a backend sync refusal is never shown as successful deletion", async () => {
  const h = deletionFixture();
  h.context.api = async () => { throw new Error("Fixture synchronization active"); };
  await h.context.performAction("delete", "fixture-0");
  assert.equal(h.toasts.length, 1);
  assert.equal(h.toasts[0].type, "error");
  assert.match(h.toasts[0].message, /已确认彻底删除 0 个.*1 个结果未确认/);
  assert.equal(h.state.deletedIds.size, 0);
  assert.equal(h.state.selected.has("fixture-0"), true);
  assert.equal(h.state.deleteBusy, false);
});

test("a late Cookie read cannot restore data into a draft removed by deletion", async () => {
  const h = deletionFixture(), file = deferred();
  h.state.draft = { id: "fixture-0", cookie_text: "fixture before" };
  h.element("#profile-drawer").hidden = false;
  const reading = h.context.readCookieFile({ size: 1, text: () => file.promise });
  await h.context.performAction("delete", "fixture-0");
  file.resolve("fixture late content"); await reading;
  assert.equal(h.state.draft, null);
  assert.equal(h.element("#profile-form").innerHTML, "");
  assert.equal(h.element("#profile-drawer").hidden, true);
  assert.equal(h.toasts.length, 1);
});

test("pending deletion blocks open, editing, save and bulk open while allowing deletion retry", async () => {
  const h = deletionFixture(), calls = [];
  h.state.profiles[0].delete_pending = true;
  h.context.api = async (action) => { calls.push(action); return { deleted: true, cleanup_complete: true }; };
  for (const action of ["open", "activate", "edit", "proxy", "restore"]) await h.context.performAction(action, "fixture-0");
  await h.context.batchAction("open", h.element("batch"));
  h.context.openDrawer(h.state.profiles[0]);
  assert.equal(h.state.draft, null);
  h.state.draft = { id: "fixture-0", name: "Before fixture" };
  h.context.readField({ disabled: false, dataset: { field: "name" }, value: "After fixture" });
  await h.context.saveProfile();
  assert.equal(h.state.draft.name, "Before fixture");
  assert.deepEqual(calls, []);
  const rendered = h.context.profileRow(h.state.profiles[0]);
  assert.match(rendered, /删除未完成/);
  assert.match(rendered, /class="open-button[^>]*disabled/);
  await h.context.performAction("delete", "fixture-0");
  assert.deepEqual(calls, ["delete"]);
  assert.equal(h.state.deletedIds.has("fixture-0"), true);
});

test("pending archived records disable restore and preserve an enabled retry-delete control", () => {
  const h = deletionFixture(1, true);
  h.state.profiles[0].config_status = "delete_pending";
  h.context.renderRecycle();
  const rendered = h.element("#recycle-list").innerHTML;
  assert.match(rendered, /删除未完成/);
  assert.match(rendered, /data-restore="fixture-0"[^>]*disabled/);
  assert.doesNotMatch(rendered, /data-delete="fixture-0"[^>]*disabled/);
  const button = h.element("open-button");
  h.context.updateOpenButton(button, h.state.profiles[0]);
  assert.equal(button.disabled, true);
  assert.match(button.innerHTML, /删除未完成/);
});

test("status polling preserves and enforces deletion-pending markers", async () => {
  const h = deletionFixture();
  h.context.api = async () => ({ profiles: [{ id: "fixture-0", delete_pending: true, config_status: "delete_pending" }] });
  await h.context.refreshStatus();
  assert.equal(h.state.profiles[0].delete_pending, true);
  assert.equal(h.state.profiles[0].config_status, "delete_pending");
  let calls = 0;
  h.context.api = async () => { calls++; };
  await h.context.performAction("open", "fixture-0");
  assert.equal(calls, 0);
});

test("deleting the final interrupted-job record clears the missing job and loads a fresh import preview", async () => {
  const h = deletionFixture(), calls = [];
  h.context.loadSyncPreview = h.loadSyncPreview;
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 1, items: [{ name: "Removed fixture", status: "completed" }] }));
  h.context.api = async (action, payload) => {
    calls.push(action);
    if (action === "delete") return { deleted: true, cleanup_complete: true };
    if (action === "sync_status") {
      assert.equal(payload.job_id, "fixture-job");
      assert.equal(payload.missing_ok, true);
      return null;
    }
    assert.equal(action, "sync_preview");
    return { items: [{ source_key: "available-fixture", name: "Available fixture", status: "ready" }] };
  };
  await h.context.performAction("delete", "fixture-0");
  assert.deepEqual(calls, ["delete", "sync_status", "sync_preview"]);
  assert.equal(h.state.sync.jobId, null);
  assert.equal(h.state.sync.status, null);
  assert.equal(h.state.sync.pollPaused, false);
  assert.equal(h.element("#sync-result-list").innerHTML, "");
  assert.equal(h.state.sync.preview[0].source_key, "available-fixture");
  assert.equal(h.element("#sync-progress-section").hidden, true);
  assert.equal(h.element("#sync-start").disabled, false);
  assert.doesNotMatch(h.element("#sync-start").textContent, /继续/);
});

test("deletion refreshes a surviving interrupted job's counts and bounded results without discarding its remaining work", async () => {
  const h = deletionFixture(); let previews = 0;
  h.context.loadSyncPreview = h.loadSyncPreview;
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", total: 3, completed: 2, items: [{ name: "Old fixture", status: "completed" }] }));
  h.context.api = async (action, payload) => {
    if (action === "delete") return { deleted: true, cleanup_complete: true };
    if (action === "sync_preview") { previews++; return { items: [] }; }
    assert.equal(action, "sync_status");
    assert.equal(payload.missing_ok, true);
    return syncStatus({ state: "interrupted", total: 2, completed: 1, items: [{ name: "Remaining fixture", status: "completed" }] });
  };
  await h.context.performAction("delete", "fixture-0");
  assert.equal(previews, 0);
  assert.equal(h.state.sync.jobId, "fixture-job");
  assert.equal(h.state.sync.status.total, 2);
  assert.equal(h.state.sync.status.completed, 1);
  assert.equal(h.state.sync.status.state, "interrupted");
  assert.match(h.element("#sync-result-list").innerHTML, /Remaining fixture/);
  assert.doesNotMatch(h.element("#sync-result-list").innerHTML, /Old fixture/);
  assert.match(h.element("#sync-start").textContent, /继续剩余同步/);
});

test("a failed post-delete job check retains the interrupted task and a later explicit missing result can recover", async () => {
  const h = deletionFixture();
  h.context.loadSyncPreview = h.loadSyncPreview;
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 1 }));
  h.context.api = async (action) => {
    if (action === "delete") return { deleted: true, cleanup_complete: true };
    throw new Error("Fixture network failure");
  };
  await h.context.performAction("delete", "fixture-0");
  assert.equal(h.state.sync.jobId, "fixture-job");
  assert.equal(h.state.sync.status.state, "interrupted");
  assert.equal(h.state.sync.pollPaused, true);
  assert.match(h.state.sync.error, /同步任务核对失败/);
  assert.ok(h.serviceErrors.some((message) => /同步任务核对失败/.test(message)));
  h.context.api = async (action, payload) => {
    if (action === "sync_status") { assert.equal(payload.missing_ok, true); return null; }
    assert.equal(action, "sync_preview"); return { items: [] };
  };
  h.context.resumeSyncStatus(); await new Promise(setImmediate);
  assert.equal(h.state.sync.jobId, null);
  assert.equal(h.state.sync.status, null);
  assert.equal(h.state.sync.pollPaused, false);
  assert.equal(h.state.sync.error, "");
});

test("late pre-deletion status and bootstrap replies cannot resurrect a removed sync job", async () => {
  const h = deletionFixture(), oldStatus = deferred(), oldBootstrap = deferred(), confirmation = deferred();
  h.context.loadSyncPreview = h.loadSyncPreview;
  const interrupted = syncStatus({ state: "interrupted", completed: 1 });
  h.context.restoreSyncJob(interrupted);
  h.context.api = async (action, payload) => {
    if (action === "bootstrap") return oldBootstrap.promise;
    if (action === "sync_status") return payload.missing_ok && h.state.deleteBusy ? null : oldStatus.promise;
    if (action === "delete") return { deleted: true, cleanup_complete: true };
    assert.equal(action, "sync_preview"); return { items: [] };
  };
  const polling = h.context.pollSyncStatus();
  h.context.confirmAction = async () => confirmation.promise;
  const deleting = h.context.performAction("delete", "fixture-0");
  const bootstrapping = h.context.bootstrap({ quiet: true });
  confirmation.resolve(true); await deleting;
  assert.equal(h.state.sync.jobId, null);
  oldStatus.resolve(interrupted); oldBootstrap.resolve({ sync_job: interrupted });
  await Promise.all([polling, bootstrapping]);
  assert.equal(h.state.sync.jobId, null);
  assert.equal(h.state.sync.status, null);
  assert.equal(h.timers.size, 0);
});

test("a missing-task reply and an empty bootstrap cannot clear a newer running task", async () => {
  const h = deletionFixture(), checking = deferred();
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 1 }));
  h.context.api = async () => checking.promise;
  const refresh = h.context.refreshSyncAfterDelete();
  const syncRevision = h.state.sync.requestRevision;
  h.context.restoreSyncJob(syncStatus({ state: "running", completed: 2 }));
  checking.resolve(null);
  assert.equal(await refresh, false);
  h.context.acceptBootstrap({ sync_job: null }, { syncRevision });
  assert.equal(h.state.sync.jobId, "fixture-job");
  assert.equal(h.state.sync.status.state, "running");
  assert.equal(h.state.sync.status.completed, 2);
  assert.equal(h.timers.size, 1);
});

test("a fresh empty bootstrap clears an obsolete interrupted job after a failed deletion refresh", () => {
  const h = deletionFixture();
  h.context.restoreSyncJob(syncStatus({ state: "interrupted", completed: 1 }));
  h.state.sync.pollPaused = true;
  h.context.acceptBootstrap({ sync_job: null });
  assert.equal(h.state.sync.jobId, null);
  assert.equal(h.state.sync.status, null);
  assert.equal(h.state.sync.pollPaused, false);
  assert.equal(h.element("#sync-result-list").innerHTML, "");
});

test("deletion checks a locally running task that the backend has finished and removed", async () => {
  const h = deletionFixture(), calls = [];
  h.context.loadSyncPreview = h.loadSyncPreview;
  h.context.restoreSyncJob(syncStatus({ state: "running", completed: 0, total: 1 }));
  h.context.api = async (action, payload) => {
    calls.push(action);
    if (action === "delete") return { deleted: true, cleanup_complete: true };
    if (action === "sync_status") {
      assert.equal(payload.job_id, "fixture-job");
      assert.equal(payload.missing_ok, true);
      return null;
    }
    assert.equal(action, "sync_preview");
    return { items: [{ source_key: "available-fixture", status: "ready" }] };
  };
  await h.context.performAction("delete", "fixture-0");
  assert.deepEqual(calls, ["delete", "sync_status", "sync_preview"]);
  assert.equal(h.state.sync.jobId, null);
  assert.equal(h.state.sync.status, null);
  assert.equal(h.element("#sync-start").disabled, false);
  assert.equal(h.state.sync.selected.has("available-fixture"), true);
  assert.equal(h.timers.size, 0);
});

test("a post-delete check keeps a task that the backend still reports running", async () => {
  const h = deletionFixture(); let previews = 0, checks = 0;
  h.context.loadSyncPreview = h.loadSyncPreview;
  h.context.restoreSyncJob(syncStatus({ state: "running", completed: 1, total: 3 }));
  h.context.api = async (action, payload) => {
    if (action === "delete") return { deleted: true, cleanup_complete: true };
    if (action === "sync_preview") { previews++; return { items: [] }; }
    assert.equal(action, "sync_status");
    assert.equal(payload.missing_ok, true); checks++;
    return syncStatus({ state: "running", completed: 2, total: 3 });
  };
  await h.context.performAction("delete", "fixture-0");
  assert.equal(checks, 1);
  assert.equal(previews, 0);
  assert.equal(h.state.sync.jobId, "fixture-job");
  assert.equal(h.state.sync.status.state, "running");
  assert.equal(h.state.sync.status.completed, 2);
  assert.equal(h.timers.size, 1);
});

test("a failed stale-running task check preserves the job and manual status reading can confirm removal", async () => {
  const h = deletionFixture();
  h.context.loadSyncPreview = h.loadSyncPreview;
  h.context.restoreSyncJob(syncStatus({ state: "running", completed: 0, total: 1 }));
  h.context.api = async (action) => {
    if (action === "delete") return { deleted: true, cleanup_complete: true };
    throw new Error("Fixture temporary network failure");
  };
  await h.context.performAction("delete", "fixture-0");
  assert.equal(h.state.sync.jobId, "fixture-job");
  assert.equal(h.state.sync.status.state, "running");
  assert.equal(h.state.sync.pollPaused, true);
  h.context.api = async (action, payload) => {
    if (action === "sync_status") { assert.equal(payload.missing_ok, true); return null; }
    assert.equal(action, "sync_preview"); return { items: [] };
  };
  h.context.resumeSyncStatus(); await new Promise(setImmediate);
  assert.equal(h.state.sync.jobId, null);
  assert.equal(h.state.sync.status, null);
  assert.equal(h.state.sync.error, "");
  assert.equal(h.state.sync.pollPaused, false);
});

test("a fresh empty bootstrap clears a stale running task while respecting task-mutation guards", () => {
  const h = deletionFixture();
  h.context.restoreSyncJob(syncStatus({ state: "running", completed: 0, total: 1 }));
  for (const mutation of ["starting", "cancelling"]) {
    h.state.sync[mutation] = true;
    h.context.acceptBootstrap({ sync_job: null });
    assert.equal(h.state.sync.jobId, "fixture-job");
    h.state.sync[mutation] = false;
  }
  h.context.acceptBootstrap({ sync_job: null });
  assert.equal(h.state.sync.jobId, null);
  assert.equal(h.state.sync.status, null);
  assert.equal(h.timers.size, 0);
});
