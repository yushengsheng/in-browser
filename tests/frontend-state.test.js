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

test("creation randomize sits next to its fingerprint heading and imported fields stay read-only", () => {
  const h = fixture(), imported = { disabled: false };
  h.state.creatingDraft = true;
  h.state.draft = h.context.mergedProfile({ creation: { count: 1, proxy_lines: [] } });
  h.context.buildProfileForm();
  const html = h.element("#profile-form").innerHTML;
  const basic = html.match(/data-form-section="basic">(.*?)<\/section>/s)[1];
  const fingerprint = html.match(/data-form-section="fingerprint">(.*?)<\/section>/s)[1];
  assert.doesNotMatch(basic, /creation-randomize/);
  assert.match(fingerprint, /class="fingerprint-heading"><h3>指纹信息<\/h3><button id="creation-randomize"/);
  assert.match(fingerprint, /设置新窗口的浏览器环境信息/);
  h.state.creatingDraft = false;
  h.element("#profile-form").all.set("[data-form-section='fingerprint'] input,[data-form-section='fingerprint'] select,[data-form-section='fingerprint'] textarea", [imported]);
  h.context.buildProfileForm();
  assert.doesNotMatch(h.element("#profile-form").innerHTML, /creation-randomize|data-field="created_options\./);
  assert.equal(imported.disabled, true);
});

test("batch proxy lines preserve separate rows through a form rebuild and collection", () => {
  const h = fixture();
  const lines = ["http://first.example:8080", "socks5://second.example:1080"];
  h.state.creatingDraft = true;
  h.state.draft = h.context.mergedProfile({ creation: { count: 2, proxy_lines: lines } });
  for (let i = 0; i < 2; i++) {
    h.context.buildProfileForm();
    const text = h.element("#profile-form").innerHTML.match(/<textarea id="field-creation-proxy_lines"[^>]*>(.*?)<\/textarea>/s)[1];
    assert.equal(text, lines.join("\n"));
    h.element("#profile-form").all.set("[data-field]", [{ dataset: { field: "creation.proxy_lines", type: "lines" }, value: text }]);
    assert.deepEqual(Array.from(h.context.collectDraft().creation.proxy_lines), lines);
  }
});

function creationControls(h, definitions) {
  const controls = definitions.map(([field, type, initial]) => {
    let value = String(initial ?? "");
    return {
      dataset: { field, type }, disabled: false, checked: initial === true,
      get value() { return value; }, set value(next) { value = String(next ?? ""); },
      checkValidity: () => true,
    };
  });
  const form = h.element("#profile-form");
  form.all.set("[data-field]", controls);
  form.all.set('[data-field^="fingerprint."]', controls.filter(c => c.dataset.field.startsWith("fingerprint.")));
  form.all.set("[data-form-section='fingerprint'] input,[data-form-section='fingerprint'] select,[data-form-section='fingerprint'] textarea", controls.filter(c => c.dataset.field.startsWith("fingerprint.")));
  form.all.set('input[type="number"]', controls.filter(c => ["number", "nullableNumber"].includes(c.dataset.type)));
  form.all.set('[data-type^="json"]', controls.filter(c => c.dataset.type.startsWith("json")));
  for (const type of ["jsonobject", "jsontext"])
    form.all.set(`[data-type="${type}"]:not(:disabled)`, controls.filter(c => c.dataset.type === type));
  return Object.fromEntries(controls.map(c => [c.dataset.field, c]));
}

test("creation compatibility-only fields stay readable and cannot silently replace persisted values", () => {
  const h = fixture();
  h.state.creatingDraft = true;
  h.state.draft = h.context.mergedProfile({ name: "synthetic", fingerprint: {
    version: "fixture-version", osVersion: "fixture-system", timeZoneOffset: 60,
    platformVersion: "10.0.0", resolutionType: "1", devicePixelRatio: 2,
  } });
  const controls = creationControls(h, [
    ["fingerprint.version", "string", "fixture-version"], ["fingerprint.osVersion", "string", "fixture-system"],
    ["fingerprint.timeZoneOffset", "number", "60"], ["fingerprint.platformVersion", "string", "10.0.0"],
    ["fingerprint.devicePixelRatio", "number", "2"],
  ]);
  h.context.buildProfileForm();
  for (const key of ["version", "osVersion", "timeZoneOffset"]) {
    const control = controls[`fingerprint.${key}`];
    assert.equal(control.disabled, true);
    control.value = "999";
    h.context.readField(control);
  }
  assert.equal(controls["fingerprint.platformVersion"].disabled, false);
  assert.equal(controls["fingerprint.devicePixelRatio"].disabled, false);
  const collected = h.context.collectDraft();
  assert.equal(collected.fingerprint.version, "fixture-version");
  assert.equal(collected.fingerprint.osVersion, "fixture-system");
  assert.equal(collected.fingerprint.timeZoneOffset, 60);
  const html = h.element("#profile-form").innerHTML;
  assert.match(html, /仅保留原厂在线随机筛选值，本地不使用/);
  assert.match(html, /实际时区偏移由上方 IANA 时区和日期决定/);
  assert.match(html, /UA 可以相同，不代表全部指纹相同；UA 版本需匹配所选内核/);
  assert.match(html, /value="fixture-version"/);
  assert.match(html, /value="fixture-system"/);
});

test("system resolution makes DPR read-only without losing the manual draft across toggles and randomization", async () => {
  const h = fixture();
  h.state.creatingDraft = true;
  h.state.draft = h.context.mergedProfile({ fingerprint: { resolutionType: "1", devicePixelRatio: 2.5 } });
  const controls = creationControls(h, [["fingerprint.resolutionType", "string", "1"], ["fingerprint.devicePixelRatio", "number", "2.5"]]);
  const mode = controls["fingerprint.resolutionType"], dpr = controls["fingerprint.devicePixelRatio"];
  h.context.buildProfileForm();
  dpr.value = "3.5";
  h.context.readField(dpr);
  const switchMode = value => { mode.value = value; h.context.readField(mode); };
  for (const next of ["0", "2", "0", "1", "0"]) {
    switchMode(next);
    assert.equal(dpr.disabled, next === "0");
    assert.equal(dpr.value, "3.5");
    assert.equal(h.context.collectDraft().fingerprint.devicePixelRatio, 3.5);
  }
  h.context.api = async (_action, payload) => ({ fingerprint: { ...payload.fingerprint, canvasValue: 12345 } });
  await h.context.randomizeCreation();
  assert.equal(dpr.disabled, true);
  assert.equal(dpr.value, "3.5");
  switchMode("1");
  assert.equal(dpr.disabled, false);
  assert.equal(dpr.value, "3.5");
  assert.equal(h.state.draft.fingerprint.devicePixelRatio, 3.5);
  assert.match(h.element("#profile-form").innerHTML, /系统分辨率模式使用系统像素比；此处保留手动值/);
  h.state.creatingDraft = false;
  h.context.updateFingerprintReadOnly();
  assert.equal(dpr.disabled, true);
  assert.equal(mode.disabled, true);
});

test("randomized controls and all field types reach creation payload without rebuilding unrelated fields", async () => {
  const h = fixture(), requests = [];
  h.state.creatingDraft = true;
  h.state.creation.requestId = "a".repeat(32);
  h.state.draft = h.context.mergedProfile({ name: "synthetic", creation: { count: 2, random_each: false, proxy_lines: [] }, created_options: { workbench: "disable" } });
  const controls = creationControls(h, [
    ["name", "string", "synthetic typed name"], ["tags", "list", "first,second"],
    ["creation.count", "number", "2"], ["creation.random_each", "boolean", false],
    ["creation.proxy_lines", "lines", "http://first.example:8080\nsocks5://second.example:1080"],
    ["fingerprint.hardwareConcurrency", "number", "12"], ["fingerprint.deviceMemory", "number", "0.5"],
    ["fingerprint.lat", "number", "0"], ["fingerprint.lng", "number", ""],
    ["fingerprint.canvasValue", "nullableNumber", ""], ["fingerprint.clientRectNoiseEnabled", "boolean", false],
    ["fingerprint.webgpu", "jsonobject", '{"fixture":true}'],
    ["fingerprint.mediaDeviceValue", "jsontext", ""], ["fingerprint.speechVoicesValue", "jsontext", '[{"voice":"synthetic"}]'],
    ["fingerprint.plugins", "jsonarray", '[{"name":"synthetic"}]'],
    ["created_options.image_limit_kb", "number", "64"], ["created_options.clear_cache", "boolean", true],
    ["preferences.disable_gpu", "boolean", true], ["cookie_text", "string", "synthetic cookie draft"],
  ]);
  h.element("#profile-form").innerHTML = "unchanged form";
  h.element("#drawer-proxy-result").textContent = "synthetic proxy status";
  h.context.api = async (action, payload) => {
    requests.push(JSON.parse(JSON.stringify({ action, payload })));
    if (action === "creation_randomize") return { fingerprint: { ...payload.fingerprint, hardwareConcurrency: 16, deviceMemory: 8,
      canvasValue: 45678, clientRectNoiseEnabled: true, webgpu: { fixture: false } } };
    return { job_id: "synthetic", state: "completed", total: 2, completed: 2, failed: 0, items: [] };
  };
  h.context.pollCreation = async () => {};
  await h.context.randomizeCreation();
  assert.equal(requests[0].payload.fingerprint.hardwareConcurrency, 12);
  assert.equal(requests[0].payload.fingerprint.deviceMemory, 0.5);
  assert.equal(controls["fingerprint.hardwareConcurrency"].value, "16");
  assert.equal(controls["fingerprint.canvasValue"].value, "45678");
  assert.equal(controls["fingerprint.clientRectNoiseEnabled"].checked, true);
  assert.deepEqual(JSON.parse(controls["fingerprint.webgpu"].value), { fixture: false });
  assert.equal(h.element("#profile-form").innerHTML, "unchanged form");
  assert.equal(h.element("#drawer-proxy-result").textContent, "synthetic proxy status");
  assert.equal(h.state.saving, false);
  assert.equal(h.element("#profile-form").inert, false);
  await h.context.saveProfile();
  const submitted = requests.find(r => r.action === "create_windows").payload;
  assert.equal(submitted.count, 2);
  assert.equal(submitted.random_each, false);
  assert.deepEqual(submitted.proxy_lines, ["http://first.example:8080", "socks5://second.example:1080"]);
  assert.equal(submitted.profile.creation, undefined);
  assert.equal(submitted.profile.name, "synthetic typed name");
  assert.deepEqual(submitted.profile.tags, ["first", "second"]);
  assert.equal(submitted.profile.fingerprint.hardwareConcurrency, 16);
  assert.equal(submitted.profile.fingerprint.deviceMemory, 8);
  assert.equal(submitted.profile.fingerprint.lat, 0);
  assert.equal(submitted.profile.fingerprint.lng, "");
  assert.equal(submitted.profile.fingerprint.mediaDeviceValue, null);
  assert.equal(submitted.profile.fingerprint.speechVoicesValue, '[{"voice":"synthetic"}]');
  assert.equal(submitted.profile.fingerprint.plugins, '[{"name":"synthetic"}]');
  assert.deepEqual(submitted.profile.fingerprint.webgpu, { fixture: false });
  assert.equal(submitted.profile.created_options.image_limit_kb, 64);
  assert.equal(submitted.profile.created_options.clear_cache, true);
  assert.equal(submitted.profile.preferences.disable_gpu, true);
  assert.equal(submitted.profile.cookie_text, "synthetic cookie draft");
});

test("late randomization cannot overwrite edits or apply an earlier result after a change and undo", async () => {
  for (const undo of [false, true]) {
    const h = fixture(), pending = deferred();
    h.state.creatingDraft = true;
    h.state.draft = h.context.mergedProfile({ fingerprint: { hardwareConcurrency: 8 } });
    const controls = creationControls(h, [["fingerprint.hardwareConcurrency", "number", "8"]]);
    let requests = 0;
    h.context.api = async () => { requests++; return pending.promise; };
    const randomizing = h.context.randomizeCreation();
    assert.equal(h.element("#profile-form").inert, true);
    await h.context.randomizeCreation();
    assert.equal(requests, 1);
    controls["fingerprint.hardwareConcurrency"].value = "12";
    h.context.readField(controls["fingerprint.hardwareConcurrency"]);
    if (undo) {
      controls["fingerprint.hardwareConcurrency"].value = "8";
      h.context.readField(controls["fingerprint.hardwareConcurrency"]);
    }
    pending.resolve({ fingerprint: { hardwareConcurrency: 16 } });
    await randomizing;
    assert.equal(h.state.draft.fingerprint.hardwareConcurrency, undo ? 8 : 12);
    assert.match(h.element("#drawer-error").textContent, /随机结果未应用/);
    assert.equal(h.state.saving, false);
  }
});

test("randomization failure keeps the draft and an old response cannot reset a newer drawer", async () => {
  for (const late of [false, true]) {
    const h = fixture(), pending = deferred();
    h.state.creatingDraft = true;
    h.state.draft = h.context.mergedProfile({ name: "first" });
    h.context.api = async () => pending.promise;
    const randomizing = h.context.randomizeCreation();
    if (late) {
      h.state.draft = h.context.mergedProfile({ name: "second" });
      h.state.drawerSession++;
      h.context.showDrawerError("new drawer error");
    }
    pending.reject(new Error("synthetic random failure"));
    await randomizing;
    assert.equal(h.state.draft.name, late ? "second" : "first");
    assert.equal(h.state.saving, late);
    assert.equal(h.element("#profile-form").inert, late);
    assert.equal(h.element("#drawer-error").textContent, late ? "new drawer error" : "synthetic random failure");
  }
});

test("numeric input rejects incomplete browser numbers and location accuracy matches backend limits", () => {
  const h = fixture();
  h.state.creatingDraft = true;
  h.state.draft = h.context.mergedProfile({ name: "synthetic" });
  h.context.buildProfileForm();
  assert.match(h.element("#profile-form").innerHTML, /id="field-fingerprint-defaultAccuracy"[^>]*min="1" max="100000"/);
  for (const field of ["hardwareConcurrency", "deviceMemory"]) {
    const control = {
      value: "", disabled: false, validity: { badInput: true }, checkValidity: () => false,
      dataset: { field: `fingerprint.${field}` },
      closest: selector => selector === "[data-form-section]" ? { dataset: { formSection: "fingerprint" } } : { querySelector: () => ({ textContent: field }) },
    };
    h.element("#profile-form").all.set('input[type="number"]', [control]);
    assert.equal(h.context.validateDraft(h.state.draft).field, `fingerprint.${field}`);
    control.validity.badInput = false;
    assert.equal(h.context.validateDraft(h.state.draft), null);
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
        removeAttribute(key) { delete this[key]; },
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

function windowLayoutData(settings = {}) {
  return {
    settings: { mode: "auto", monitor: "primary", start_x: 0, start_y: 0, width: 640, height: 600,
      columns: 3, gap_x: 0, gap_y: 0, step_x: 30, step_y: 30, order: "asc", ...settings },
    monitors: [{ id: "display-one", label: "显示器 1", primary: true, x: 0, y: 0, width: 1920, height: 1040 }],
  };
}

test("arrange uses all package windows regardless of filters or selection and prevents duplicate requests", async () => {
  const h = fixture(), pending = deferred(), requests = [];
  h.state.search = "no results";
  h.state.selected.add("one-selected-window");
  h.state.filter = "running";
  h.context.api = async (...args) => { requests.push(args); return pending.promise; };
  const arranging = h.element("#arrange-windows").onclick();
  await h.context.arrangeWindows();
  assert.deepEqual(requests, [["arrange_windows"]]);
  assert.equal(h.element("#arrange-windows").disabled, true);
  assert.equal(h.element("#window-layout-settings").disabled, true);
  pending.resolve({ arranged: 2, failed: 1, skipped: 1, total: 4, adjusted: 0 });
  await arranging;
  assert.match(h.toasts[0].message, /已排列 2 个窗口，失败 1 个，跳过 1 个/);
  assert.equal(h.toasts[0].type, "error");
  assert.equal(h.state.windowLayout.arranging, false);
  assert.equal(h.element("#arrange-windows").disabled, false);
  assert.equal(h.state.search, "no results");
  assert.equal(h.state.selected.size, 1);
});

test("layout result keeps backend diagnostics without duplicating counts or inventing empty state", () => {
  const h = fixture();
  for (const result of [
    { arranged: 2, failed: 1, skipped: 1, total: 4, message: "已排列 2 个窗口，失败 1 个，跳过 1 个" },
    { arranged: 0, failed: 0, skipped: 0, total: 0, message: "无法读取部分进程，未确认窗口归属" },
  ]) {
    h.context.reportWindowArrangement(result);
    assert.equal(h.toasts.at(-1).message, result.message);
  }
});

test("layout modes show only applicable fields and cancelling never saves", async () => {
  const h = fixture(), requests = [];
  h.context.api = async (action) => { requests.push(action); return windowLayoutData(); };
  await h.context.openWindowLayout();
  assert.equal(h.element("#window-layout-manual").hidden, true);
  assert.equal(h.element("#window-layout-auto-note").hidden, false);
  for (const mode of ["grid", "cascade"]) {
    h.element("#window-layout-mode").value = mode;
    h.element("#window-layout-mode").onchange();
    assert.equal(h.element("#window-layout-manual").hidden, false);
    assert.equal(h.element("#window-layout-grid").hidden, mode !== "grid");
    assert.equal(h.element("#window-layout-cascade").hidden, mode !== "cascade");
  }
  h.element("#window-layout-width").value = "850";
  h.element("#window-layout-cancel").onclick();
  assert.equal(h.element("#window-layout-dialog").open, false);
  assert.deepEqual(requests, ["window_layout_get"]);
  await h.context.openWindowLayout();
  assert.equal(h.element("#window-layout-width").value, "640");
});

test("closing a layout read ignores its late reply after a newer dialog opens", async () => {
  const h = fixture(), pending = deferred();
  h.context.api = async () => pending.promise;
  const oldRead = h.context.openWindowLayout();
  h.context.closeWindowLayout();
  h.context.api = async () => windowLayoutData({ mode: "grid", width: 880 });
  await h.context.openWindowLayout();
  pending.resolve(windowLayoutData({ mode: "cascade", width: 500 }));
  await oldRead;
  assert.equal(h.element("#window-layout-dialog").open, true);
  assert.equal(h.element("#window-layout-mode").value, "grid");
  assert.equal(h.element("#window-layout-width").value, "880");
  assert.equal(h.state.windowLayout.loading, false);
});

test("layout save and arrange preserves API ordering, integer fields and busy locking", async () => {
  const h = fixture(), pendingSave = deferred(), pendingArrange = deferred(), requests = [];
  h.context.api = async () => windowLayoutData({ mode: "grid" });
  await h.context.openWindowLayout();
  h.element("#window-layout-width").value = "480";
  h.element("#window-layout-columns").value = "4";
  h.element("#window-layout-order").value = "desc";
  h.context.api = async (action, payload) => {
    requests.push({ action, payload });
    return action === "window_layout_save" ? pendingSave.promise : pendingArrange.promise;
  };
  const saving = h.context.saveWindowLayout(true);
  await h.context.saveWindowLayout(true);
  h.context.closeWindowLayout();
  assert.equal(h.element("#window-layout-dialog").open, true);
  assert.equal(h.element("#window-layout-form").inert, true);
  assert.equal(h.element("#window-layout-cancel").disabled, true);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].payload.settings.width, 480);
  assert.equal(requests[0].payload.settings.columns, 4);
  assert.equal(requests[0].payload.settings.order, "desc");
  pendingSave.resolve({ settings: requests[0].payload.settings });
  await new Promise(setImmediate);
  assert.deepEqual(requests.map((request) => request.action), ["window_layout_save", "arrange_windows"]);
  assert.equal(requests[1].payload, undefined);
  assert.equal(h.state.windowLayout.arranging, true);
  pendingArrange.resolve({ arranged: 4, failed: 0, skipped: 0, total: 4, adjusted: 0 });
  await saving;
  assert.equal(h.element("#window-layout-dialog").open, false);
  assert.equal(h.state.windowLayout.saving, false);
  assert.equal(h.state.windowLayout.arranging, false);
});

test("invalid layout dimensions block saving but unused fields do not block auto", async () => {
  const h = fixture(), requests = [];
  h.context.api = async () => windowLayoutData({ mode: "grid" });
  await h.context.openWindowLayout();
  h.context.api = async (action, payload) => { requests.push(action); return { settings: payload.settings }; };
  for (const [key, value] of [["width", "119"], ["height", "39"], ["columns", "2.5"], ["start_x", "-1"], ["gap_x", ""]]) {
    const control = h.element("#window-layout-" + key), previous = control.value;
    control.value = value;
    await h.context.saveWindowLayout();
    assert.equal(h.element("#window-layout-error").hidden, false);
    assert.equal(requests.length, 0);
    control.value = previous;
  }
  h.element("#window-layout-mode").value = "auto";
  h.element("#window-layout-width").value = "";
  await h.context.saveWindowLayout();
  assert.deepEqual(requests, ["window_layout_save"]);
  assert.equal(h.element("#window-layout-dialog").open, false);
});

test("layout failures retain the draft and distinguish a saved layout from failed arrangement", async () => {
  const h = fixture();
  h.context.api = async () => windowLayoutData({ mode: "cascade" });
  await h.context.openWindowLayout();
  h.element("#window-layout-step_x").value = "45";
  h.context.api = async () => { throw new Error("合成保存失败"); };
  await h.context.saveWindowLayout(true);
  assert.match(h.element("#window-layout-error").textContent, /合成保存失败/);
  assert.equal(h.element("#window-layout-step_x").value, "45");
  assert.equal(h.element("#window-layout-save").disabled, false);
  h.context.api = async (action, payload) => {
    if (action === "window_layout_save") return { settings: payload.settings };
    throw new Error("合成排列失败");
  };
  await h.context.saveWindowLayout(true);
  assert.match(h.element("#window-layout-error").textContent, /设置已保存，排列未完成/);
  assert.equal(h.element("#window-layout-dialog").open, true);
  assert.equal(h.element("#window-layout-form").inert, false);
  assert.equal(h.state.windowLayout.arranging, false);
});

test("missing layout monitor uses primary and escapes display names", async () => {
  const h = fixture(), data = windowLayoutData({ monitor: "unplugged" });
  data.monitors[0].label = '<display & "one">';
  h.context.api = async () => data;
  await h.context.openWindowLayout();
  assert.equal(h.element("#window-layout-monitor").value, "primary");
  assert.equal(h.element("#window-layout-monitor-note").hidden, false);
  assert.match(h.element("#window-layout-monitor").innerHTML, /&lt;display &amp; &quot;one&quot;&gt;/);
  assert.doesNotMatch(h.element("#window-layout-monitor").innerHTML, /<display/);
});

test("layout monitor labels use service text once and generate details only when missing", async () => {
  const h = fixture(), data = windowLayoutData();
  data.monitors[0].label = "显示器 1 · 主屏 · 1920 × 1040";
  data.monitors.push({ id: "display-two", primary: false, width: 1280, height: 720 });
  h.context.api = async () => data;
  await h.context.openWindowLayout();
  const html = h.element("#window-layout-monitor").innerHTML;
  assert.match(html, /<option value="display-one">显示器 1 · 主屏 · 1920 × 1040<\/option>/);
  assert.match(html, /<option value="display-two">显示器 · 1280 × 720<\/option>/);
});

test("batch search matches any remark and ignores case, blank lines and duplicates", () => {
  const h = fixture();
  h.state.profiles = Array.from({ length: 6 }, (_, index) => ({
    id: `search-${index}`, seq: index + 1, name: `Synthetic window ${index + 1}`,
    remark: `person${index + 1}@example.invalid`, archived: index === 5,
  }));
  h.state.search = " PERSON4@example.invalid\r\nperson2@example.invalid\n\n person1@example.invalid ; person3@example.invalid，PERSON4@example.invalid ";
  assert.deepEqual(Array.from(h.context.filteredProfiles(), (p) => p.id),
    ["search-0", "search-1", "search-2", "search-3"]);
  h.state.search = "person6@example.invalid";
  assert.equal(h.context.filteredProfiles().length, 0);
});

test("batch search supports ten proxy IPs and rejects eleven without truncation", () => {
  const h = fixture();
  h.state.profiles = Array.from({ length: 11 }, (_, index) => ({
    id: `search-${index}`, seq: index + 1, proxy: { host: `192.0.2.${index + 1}`, port: 8000 },
  }));
  const queries = h.state.profiles.map((p) => p.proxy.host);
  h.state.search = queries.slice(0, 10).join("\n");
  assert.equal(h.context.filteredProfiles().length, 10);
  h.state.search += "\n" + queries[0].toUpperCase();
  assert.equal(h.context.filteredProfiles().length, 10);
  h.state.search = queries.join("\n");
  assert.equal(h.context.filteredProfiles().length, 0);
  h.renderProfiles();
  assert.equal(h.element("#search-input")["aria-invalid"], "true");
  assert.equal(h.element("#search-feedback").hidden, false);
  assert.match(h.element("#search-feedback").textContent, /最多支持 10 项，当前 11 项/);
  assert.equal(h.element("#profile-rows").innerHTML, "");
  assert.equal(h.element("#empty-state h3").textContent, "搜索项超过上限");
});

test("batch search keeps field coverage, phrase matching, filters and sorting", () => {
  const h = fixture();
  h.state.profiles = [
    { id: "first", seq: 1, name: "Blue room", remark: "shared", group: "A", tags: ["work"], status: "running", proxy: { host: "192.0.2.31", port: 8101 } },
    { id: "second", seq: 2, name: "Blue other room", remark: "shared", group: "B", tags: ["work"], status: "running" },
    { id: "third", seq: 3, name: "Third", remark: "shared", group: "A", tags: ["other"], status: "running" },
    { id: "fourth", seq: 4, name: "Fourth", remark: "shared", group: "A", tags: ["work"], status: "closed" },
  ];
  h.state.search = "blue room";
  assert.deepEqual(Array.from(h.context.filteredProfiles(), (p) => p.id), ["first"]);
  for (const term of ["blue room", "1", "192.0.2.31", "8101", "work", "A"]) {
    h.state.search = `missing; ${term}`;
    assert.ok(h.context.filteredProfiles().some((p) => p.id === "first"));
  }
  h.state.search = "shared\nmissing";
  h.state.group = "A"; h.state.tag = "work"; h.state.filter = "running";
  assert.deepEqual(Array.from(h.context.filteredProfiles(), (p) => p.id), ["first"]);
  h.state.group = ""; h.state.tag = ""; h.state.filter = "all";
  h.state.sort = "seq"; h.state.direction = -1;
  assert.deepEqual(Array.from(h.context.filteredProfiles(), (p) => p.id), ["fourth", "third", "second", "first"]);
  h.state.search = "\n ; ， \n";
  assert.equal(h.context.filteredProfiles().length, 4);
});

test("reused collator preserves Chinese, numeric, missing and equal value sort order", () => {
  const h = fixture();
  const values = ["窗口10", "窗口2", "中文", "Alpha", "alpha", "窗口02", "", null, "阿", "2026-11-2", "2026-11-10"];
  for (const field of ["name", "group", "remark", "created_at", "last_opened_at"]) {
    h.state.profiles = values.map((value, index) => ({ id: `sort-${index}`, seq: values.length - index, [field]: value }));
    h.state.sort = field;
    for (const direction of [1, -1]) {
      h.state.direction = direction;
      const expected = [...h.state.profiles].sort((a, b) =>
        String(a[field] ?? "").localeCompare(String(b[field] ?? ""), "zh-CN", { numeric: true }) * direction);
      assert.deepEqual(Array.from(h.context.filteredProfiles(), p => p.id), expected.map(p => p.id));
    }
  }
  h.state.sort = "seq";
  h.state.direction = 1;
  assert.deepEqual(Array.from(h.context.filteredProfiles(), p => p.seq), values.map((_, index) => index + 1));
});

test("multiline search resets pagination and clearing filters restores the input", () => {
  const h = fixture();
  h.context.renderProfiles = h.renderProfiles;
  const input = h.element("#search-input");
  h.state.page = 4;
  input.value = "one\ntwo\nthree\nfour\nfive";
  input.oninput({ target: input });
  assert.equal(h.state.search, "");
  assert.equal(h.state.page, 4);
  assert.equal(input.rows, 4);
  assert.equal(h.timers.size, 1);
  [...h.timers.values()][0].callback();
  assert.equal(h.state.search, input.value);
  assert.equal(h.state.page, 1);
  assert.equal(input.rows, 4);
  assert.match(h.element("#search-feedback").textContent, /批量搜索 5 项/);
  h.element("#clear-filters").onclick();
  assert.equal(h.state.search, "");
  assert.equal(input.value, "");
  assert.equal(input.rows, 1);
  assert.equal(input["aria-invalid"], "false");
  assert.equal(h.element("#search-feedback").hidden, true);
});

test("debounced search selects the displayed page until the latest input is applied", () => {
  const h = fixture();
  h.context.renderProfiles = h.renderProfiles;
  h.state.profiles = Array.from({ length: 5 }, (_, index) => ({ id: `row-${index + 1}`, seq: index + 1, name: `窗口 ${index + 1}` }));
  h.state.pageSize = 2;
  h.state.page = 2;
  h.renderProfiles();
  let renders = 0;
  h.context.renderProfiles = () => { renders++; h.renderProfiles(); };
  const input = h.element("#search-input");
  input.value = "窗口";
  input.oninput({ target: input });
  const old = [...h.timers.values()][0];
  input.value = "窗口 5";
  input.oninput({ target: input });
  old.callback();
  assert.equal(renders, 0);
  assert.equal(h.state.search, "");
  assert.equal(h.state.page, 2);
  assert.equal(h.timers.size, 1);
  const pending = [...h.timers.values()][0];
  assert.equal(pending.delay, 150);
  h.element("#select-all").onchange({ target: { checked: true } });
  assert.deepEqual([...h.state.selected], ["row-3", "row-4"]);
  assert.match(h.element("#profile-rows").innerHTML, /<tr data-id="row-3"/);
  assert.doesNotMatch(h.element("#profile-rows").innerHTML, /<tr data-id="row-5"/);
  pending.callback();
  assert.equal(renders, 2);
  assert.equal(h.timers.size, 0);
  assert.equal(h.state.search, "窗口 5");
  assert.equal(h.state.page, 1);
  assert.equal(h.element("#select-all").checked, false);
  assert.deepEqual([...h.state.selected], ["row-3", "row-4"]);
  h.element("#select-all").onchange({ target: { checked: true } });
  assert.deepEqual([...h.state.selected], ["row-3", "row-4", "row-5"]);
});

test("clearing input or resetting filters cancels late search without changing later pagination", () => {
  for (const reset of [false, true]) {
    const h = fixture();
    h.context.renderProfiles = h.renderProfiles;
    h.state.search = "applied";
    const input = h.element("#search-input");
    input.value = "pending";
    input.oninput({ target: input });
    const pending = [...h.timers.values()][0];
    if (reset) h.element("#clear-filters").onclick();
    else {
      input.value = "";
      input.oninput({ target: input });
    }
    assert.equal(h.state.search, "");
    assert.equal(h.timers.size, 0);
    assert.equal(input.rows, 1);
    h.state.page = 2;
    pending.callback();
    assert.equal(h.state.search, "");
    assert.equal(h.state.page, 2);
  }
});

test("Chinese composition cancels pending input and commits once after the final input event", () => {
  const h = fixture(), input = h.element("#search-input");
  let renders = 0;
  h.context.renderProfiles = () => { renders++; };
  input.value = "previous";
  input.oninput({ target: input });
  const pending = [...h.timers.values()][0];
  input.oncompositionstart();
  for (const value of ["chuang", "窗口"]) {
    input.value = value;
    input.oninput({ target: input, isComposing: true });
    assert.equal(h.timers.size, 0);
  }
  pending.callback();
  assert.equal(h.state.search, "");
  assert.equal(renders, 0);
  input.oncompositionend({ target: input });
  const ended = [...h.timers.values()][0];
  input.oninput({ target: input, isComposing: false });
  assert.equal(h.timers.size, 1);
  ended.callback();
  assert.equal(renders, 0);
  [...h.timers.values()][0].callback();
  assert.equal(h.state.search, "窗口");
  assert.equal(renders, 1);
  assert.equal(h.timers.size, 0);
});

test("pending batch search retains filters and pagination selection before enforcing the ten term limit", () => {
  const h = fixture(), input = h.element("#search-input");
  h.context.renderProfiles = h.renderProfiles;
  h.state.profiles = Array.from({ length: 11 }, (_, index) => ({
    id: `row-${index + 1}`, seq: index + 1, name: `term-${index + 1}`, group: index % 2 ? "B" : "A", tags: ["work"],
  }));
  input.value = h.state.profiles.slice(0, 10).map(p => p.name).join("\n");
  input.oninput({ target: input });
  h.element("#group-filter").onchange({ target: { value: "A" } });
  h.element("#tag-filter").onchange({ target: { value: "work" } });
  h.element("#page-size").onchange({ target: { value: "1" } });
  h.element("#next-page").onclick();
  assert.equal(h.state.page, 2);
  h.element("#select-all").onchange({ target: { checked: true } });
  assert.deepEqual([...h.state.selected], ["row-3"]);
  [...h.timers.values()][0].callback();
  assert.equal(h.state.page, 1);
  assert.equal(h.state.group, "A");
  assert.equal(h.state.tag, "work");
  assert.equal(h.state.pageSize, 1);
  assert.equal(h.element("#search-input")["aria-invalid"], "false");
  input.value += "\nterm-11";
  input.oninput({ target: input });
  [...h.timers.values()][0].callback();
  assert.equal(h.element("#search-input")["aria-invalid"], "true");
  assert.equal(h.element("#profile-rows").innerHTML, "");
  assert.deepEqual([...h.state.selected], ["row-3"]);
});

test("arrangement keeps a pending search independent of the all-window request", async () => {
  const h = fixture(), input = h.element("#search-input"), requests = [];
  h.state.search = "applied";
  input.value = "pending";
  input.oninput({ target: input });
  h.context.api = async (...args) => { requests.push(args); return { arranged: 1, total: 1 }; };
  await h.element("#arrange-windows").onclick();
  assert.deepEqual(requests, [["arrange_windows"]]);
  assert.equal(h.state.search, "applied");
  assert.equal(h.timers.size, 1);
  [...h.timers.values()][0].callback();
  assert.equal(h.state.search, "pending");
});

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
  assert.match(h.element("#sync-source-note").textContent, /先自动检测本机来源.*开始同步.*才复制资料/);
  assert.match(h.element("#sync-explanation").textContent, /在比特中打开过的新窗口均会参与检查/);
  assert.match(h.element("#sync-explanation").textContent, /读取名称、备注，不复制窗口资料/);
  assert.match(h.element("#sync-explanation").textContent, /读取名称、备注可能需要比特的有效登录会话及联网/);
  assert.doesNotMatch(h.element("#sync-explanation").textContent, /检测只读取本机资料/);
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

function syncProgress(overrides = {}) {
  return {
    index: 1, source_key: "progress-fixture", name: "合成导入窗口", phase: "copying",
    done: 512 * 1024 * 1024, total: 1024 * 1024 * 1024, unit: "bytes",
    elapsed_seconds: 74, phase_elapsed_seconds: 12, timings: { checking: 2, source_hash: 60 },
    ...overrides,
  };
}

test("sync progress separates processed batch counts from measured byte progress and success", () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ total: 4, completed: 1, skipped: 1, failed: 1, progress: syncProgress({ index: 4 }) }));
  assert.equal(h.element("#sync-progress-count").textContent, "批次已处理 3 / 4 · 75%");
  assert.equal(h.element("#sync-progress").value, 3);
  assert.equal(h.element("#sync-progress-summary").textContent, "成功 1 个，跳过 1 个，失败 1 个。");
  assert.equal(h.element("#sync-current").hidden, false);
  assert.equal(h.element("#sync-current-label").textContent, "当前窗口 4 / 4");
  assert.equal(h.element("#sync-stage-count").textContent, "512 MB / 1 GB · 50%");
  assert.equal(h.element("#sync-stage-progress").value, 512 * 1024 * 1024);
  assert.equal(h.element("#sync-stage-progress").max, 1024 * 1024 * 1024);
  assert.equal(h.element("#sync-stage-elapsed").textContent, "当前窗口已用 1 分 14 秒 · 本阶段已用 12 秒");
  assert.match(h.element("#sync-stage-timings").textContent, /检查资料 2 秒.*读取来源校验摘要 1 分 0 秒/);
  assert.equal(h.timers.size, 1);
});

test("copying at 100 percent cannot complete a batch and the next phase resets its measurement", () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ total: 1, progress: syncProgress({ done: 1024, total: 1024 }) }));
  assert.match(h.element("#sync-stage-count").textContent, /100%/);
  assert.match(h.element("#sync-progress-count").textContent, /0 \/ 1 · 0%/);
  assert.doesNotMatch(h.element("#sync-phase").textContent, /同步完成/);
  h.context.restoreSyncJob(syncStatus({ total: 1, phase: "importing", progress: syncProgress({ phase: "cookies", done: null, total: null, unit: null, phase_elapsed_seconds: 0 }) }));
  assert.equal(h.element("#sync-stage-name").textContent, "准备登录资料");
  assert.equal(h.element("#sync-stage-progress").value, undefined);
  assert.equal(h.element("#sync-stage-progress").max, 1);
  assert.equal(h.element("#sync-stage-count").textContent, "总量待确认");
  assert.match(h.element("#sync-stage-elapsed").textContent, /本阶段已用 0 秒/);
});

test("large import batches retain exact processed totals and distinct final failures", () => {
  for (const total of [9999, 10000]) {
    const h = fixture();
    h.context.restoreSyncJob(syncStatus({ total, progress: syncProgress({ done: 1024, total: 1024 }) }));
    assert.equal(h.element("#sync-progress-count").textContent, `批次已处理 0 / ${total} · 0%`);
    assert.match(h.element("#sync-stage-count").textContent, /100%/);
    h.context.restoreSyncJob(syncStatus({ total, completed: total - 2, skipped: 1, progress: syncProgress({ index: total }) }));
    assert.equal(h.element("#sync-progress-count").textContent, `批次已处理 ${total - 1} / ${total} · 99.9%`);
    h.state.sync.status = h.context.boundedSyncStatus(syncStatus({ state: "completed", total, completed: total - 2, skipped: 1, failed: 1, progress: syncProgress() }));
    h.context.renderSyncProgress();
    assert.equal(h.element("#sync-progress-count").textContent, `批次已处理 ${total} / ${total} · 100%`);
    assert.equal(h.element("#sync-progress-summary").textContent, `成功 ${total - 2} 个，跳过 1 个，失败 1 个。`);
    assert.equal(h.element("#sync-phase").textContent, "同步完成，部分窗口失败");
    assert.equal(h.element("#sync-current").hidden, true);
  }
});

test("import headings display detailed stages while retaining legacy phase aliases", () => {
  const h = fixture();
  for (const [phase, label] of [["validating", "验证窗口配置"], ["committing", "提交本地窗口"]]) {
    h.context.restoreSyncJob(syncStatus({ phase, progress: null }));
    assert.equal(h.element("#sync-phase").textContent, `${label}…`);
    h.context.restoreSyncJob(syncStatus({ phase: "importing", progress: syncProgress({ phase }) }));
    assert.equal(h.element("#sync-phase").textContent, `${label}…`);
  }
  for (const [phase, label] of [["preview", "正在检查资料"], ["saving", "正在保存本地副本"], ["finalizing", "正在完成同步"]]) {
    h.context.restoreSyncJob(syncStatus({ phase, progress: null }));
    assert.equal(h.element("#sync-phase").textContent, label);
  }
});

test("zero, unknown and invalid phase totals remain indeterminate without invented percentages", () => {
  for (const values of [
    { done: 0, total: 0, unit: "bytes" },
    { done: 12, total: null, unit: "files" },
    { done: null, total: 100, unit: "bytes" },
    { done: -1, total: 100, unit: "bytes" },
    { done: 2, total: Infinity, unit: "files" },
    { done: 1, total: 3, unit: null },
  ]) {
    const h = fixture();
    h.context.restoreSyncJob(syncStatus({ progress: syncProgress(values) }));
    assert.equal(h.element("#sync-stage-progress").value, undefined);
    assert.doesNotMatch(h.element("#sync-stage-count").textContent, /%/);
    assert.match(h.element("#sync-stage-count").textContent, /总量待确认|无可计量数据/);
    if (values.total === 0) assert.match(h.element("#sync-stage-count").textContent, /^0 B/);
  }
});

test("file and baseline round progress uses reported counts without elapsed-time extrapolation", () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ progress: syncProgress({ phase: "source_verify", done: 9999, total: 10000, unit: "files" }) }));
  assert.equal(h.element("#sync-stage-count").textContent, "9999 个文件 / 10000 个文件 · 99.9%");
  h.context.restoreSyncJob(syncStatus({ progress: syncProgress({ phase: "baseline_second", done: 1, total: 3, unit: "steps", elapsed_seconds: 3661, phase_elapsed_seconds: 3600, timings: {} }) }));
  assert.equal(h.element("#sync-stage-name").textContent, "第二次环境基线采集");
  assert.equal(h.element("#sync-stage-count").textContent, "1 轮 / 3 轮 · 33.3%");
  assert.equal(h.element("#sync-stage-elapsed").textContent, "当前窗口已用 1 小时 1 分 1 秒 · 本阶段已用 1 小时 0 分 0 秒");
  assert.equal(h.element("#sync-stage-timings").hidden, true);
  assert.equal(h.element("#sync-stage-timings").textContent, "");
  h.state.sync.status.progress.elapsed_seconds = 99999;
  h.context.renderSyncProgress();
  assert.match(h.element("#sync-stage-count").textContent, /33.3%/);
});

test("current source names prefer preview labels and remain literal text with safe empty fallbacks", () => {
  const h = fixture();
  const name = '<img src=x onerror="fixture"> & 合成窗口';
  h.state.sync.names.set("progress-fixture", name);
  h.context.restoreSyncJob(syncStatus({ progress: syncProgress({ name: "待准备的本机窗口" }) }));
  assert.equal(h.element("#sync-current-name").textContent, name);
  assert.equal(h.element("#sync-current-name").title, name);
  assert.equal(h.element("#sync-current-name").innerHTML, "");
  h.state.sync.names.clear();
  h.context.restoreSyncJob(syncStatus({ progress: syncProgress({ name }) }));
  assert.equal(h.element("#sync-current-name").textContent, name);
  assert.equal(h.element("#sync-current-name").innerHTML, "");
  h.context.restoreSyncJob(syncStatus({ progress: syncProgress({ name: "" }) }));
  assert.equal(h.element("#sync-current-name").textContent, "未命名窗口");
});

test("terminal and interrupted responses clear current-item details even when stale progress is attached", async () => {
  for (const state of ["completed", "failed", "cancelled", "interrupted"]) {
    const h = fixture();
    h.context.restoreSyncJob(syncStatus({ progress: syncProgress() }));
    h.context.api = async () => syncStatus({ state, progress: syncProgress() });
    await h.context.pollSyncStatus();
    assert.equal(h.state.sync.status.progress, null);
    assert.equal(h.element("#sync-current").hidden, true);
    assert.equal(h.element("#sync-current-name").textContent, "");
    assert.equal(h.element("#sync-current-name").title, "");
    assert.equal(h.element("#sync-stage-count").textContent, "");
    assert.equal(h.element("#sync-stage-timings").textContent, "");
    assert.equal(h.element("#sync-stage-progress").value, undefined);
    assert.equal(h.timers.size, 0);
  }
});

test("legacy and restarted jobs without progress cannot retain the previous current item", () => {
  const h = fixture();
  for (const status of [syncStatus(), syncStatus({ progress: null }), syncStatus({ state: "interrupted" })]) {
    h.context.restoreSyncJob(syncStatus({ progress: syncProgress() }));
    h.context.restoreSyncJob(status);
    assert.equal(h.state.sync.status.progress, null);
    assert.equal(h.element("#sync-current").hidden, true);
    assert.equal(h.element("#sync-current-name").textContent, "");
  }
});

test("a late status response cannot replace a newer current window or phase", async () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ progress: syncProgress() }));
  const old = deferred();
  h.context.api = async () => old.promise;
  const polling = h.context.pollSyncStatus();
  h.context.restoreSyncJob(syncStatus({ completed: 1, progress: syncProgress({ index: 2, source_key: "next-fixture", name: "后续合成窗口", phase: "checking", done: null, total: null, unit: null }) }));
  old.resolve(syncStatus({ progress: syncProgress() }));
  await polling;
  assert.equal(h.element("#sync-current-name").textContent, "后续合成窗口");
  assert.equal(h.element("#sync-stage-name").textContent, "检查资料");
  assert.equal(h.element("#sync-stage-progress").value, undefined);
  assert.equal(h.state.sync.status.completed, 1);
  assert.equal(h.timers.size, 1);
});

test("cancelling remaining work preserves the current phase until it completes", async () => {
  const h = fixture();
  h.context.restoreSyncJob(syncStatus({ progress: syncProgress() }));
  h.context.api = async (action) => action === "cancel_sync" ? { requested: true } : syncStatus({ cancel_requested: true, progress: syncProgress({ done: 768 * 1024 * 1024 }) });
  await h.context.cancelSyncJob();
  await new Promise(setImmediate);
  assert.equal(h.element("#sync-current").hidden, false);
  assert.match(h.element("#sync-stage-count").textContent, /75%/);
  assert.match(h.element("#sync-background-note").textContent, /当前窗口会继续处理，只取消尚未开始的窗口/);
  assert.equal(h.element("#sync-cancel-job").disabled, true);
  assert.equal(h.timers.size, 1);
  assert.equal([...h.timers.values()][0].delay, 1000);
});

test("sync preview safely displays full source labels and long remarks with empty fallbacks", () => {
  const h = fixture();
  const name = '合成窗口 <img src=x onerror="fixture"> & \'中文\'';
  const remark = `${"长中文备注".repeat(80)}\n<script>fixture("文本")</script> & '完整尾部'`;
  const escapedName = '合成窗口 &lt;img src=x onerror=&quot;fixture&quot;&gt; &amp; &#39;中文&#39;';
  const escapedRemark = `${"长中文备注".repeat(80)}\n&lt;script&gt;fixture(&quot;文本&quot;)&lt;/script&gt; &amp; &#39;完整尾部&#39;`;
  h.state.sync.preview = [
    { source_key: "labels-fixture", name, remark, seq: 0, status: "ready" },
    { source_key: "empty-fixture", remark: " \n ", status: "ready", metadata_note: '合成提示 <读取失败> & "重试"' },
  ];
  h.context.renderSyncPreview();
  const rows = h.element("#sync-preview-rows").innerHTML;
  assert.ok(rows.includes(`<strong class="sync-source-name" title="${escapedName}">${escapedName}</strong>`));
  assert.ok(rows.includes(`<small class="sync-source-remark" title="${escapedRemark}">备注：${escapedRemark}</small>`));
  assert.match(rows, /来源序号 0/);
  assert.match(rows, /未命名窗口/);
  assert.match(rows, /来源序号 —/);
  assert.match(rows, /title="无备注">备注：—<\/small>/);
  assert.match(rows, /合成提示 &lt;读取失败&gt; &amp; &quot;重试&quot;/);
  assert.doesNotMatch(rows, /<img|<script|disabled/);
});

test("sync remark search preserves original indices and cross-page choices until explicit start", async () => {
  const h = fixture(), calls = [];
  const candidates = Array.from({ length: 105 }, (_, index) => ({
    source_key: `labels-${index}`, name: "同名合成窗口", seq: 1000 + index,
    remark: index % 2 === 0 ? "中文 Alpha 备注" : "另一组合成备注", status: "ready",
  }));
  h.context.api = async (action, payload) => {
    calls.push({ action, payload });
    if (action === "sync_preview") return { preview_id: "labels-preview", items: candidates };
    if (action === "sync_windows") return { job_id: "fixture-job" };
    return syncStatus({ state: "completed", total: 104, completed: 104 });
  };
  await h.context.loadSyncPreview();
  assert.equal(h.state.sync.selected.size, 105);
  h.element("#sync-search").oninput({ target: { value: "  ALPHA  " } });
  assert.equal(h.element("#sync-range").textContent, "1–50 / 53");
  assert.equal((h.element("#sync-preview-rows").innerHTML.match(/<tr>/g) || []).length, 50);
  assert.match(h.element("#sync-preview-rows").innerHTML, /data-sync-index="98"/);
  h.element("#sync-next").onclick();
  assert.equal(h.element("#sync-range").textContent, "51–53 / 53");
  assert.equal((h.element("#sync-preview-rows").innerHTML.match(/<tr>/g) || []).length, 3);
  for (const index of [102, 104]) {
    assert.match(h.element("#sync-preview-rows").innerHTML, new RegExp(`data-sync-index="${index}"`));
    h.element("#sync-preview-rows").onchange({
      target: { closest: () => ({ dataset: { syncIndex: String(index) }, checked: false }) },
    });
  }
  assert.equal(h.state.sync.selected.size, 103);
  assert.equal(h.state.sync.selected.has("labels-101"), true);
  h.element("#sync-search").oninput({ target: { value: "同名合成窗口" } });
  assert.equal(h.state.sync.page, 1);
  assert.equal(h.element("#sync-range").textContent, "1–50 / 105");
  h.element("#sync-search").oninput({ target: { value: "1104" } });
  const rows = h.element("#sync-preview-rows").innerHTML;
  assert.equal(h.element("#sync-range").textContent, "1–1 / 1");
  assert.match(rows, /data-sync-index="104"/);
  assert.doesNotMatch(rows, /checked/);
  h.element("#sync-preview-rows").onchange({
    target: { closest: () => ({ dataset: { syncIndex: "104" }, checked: true }) },
  });
  assert.equal(h.state.sync.selected.size, 104);
  assert.equal(h.state.sync.selected.has("labels-102"), false);
  assert.deepEqual(calls.map((call) => call.action), ["sync_preview"]);
  await h.context.startSync();
  await new Promise(setImmediate);
  const started = calls.filter((call) => call.action === "sync_windows");
  assert.equal(started.length, 1);
  assert.equal(started[0].payload.preview_id, "labels-preview");
  assert.equal(started[0].payload.source_keys.length, 104);
  assert.equal(started[0].payload.source_keys.includes("labels-102"), false);
  assert.equal(started[0].payload.source_keys.includes("labels-104"), true);
  assert.equal(started[0].payload.source_keys.includes("labels-0"), true);
});

test("sync entry only detects and explicit start submits its preview receipt once", async () => {
  const h = fixture(), calls = [];
  h.context.api = async (action, payload) => {
    calls.push({ action, payload });
    if (action === "sync_preview") return { preview_id: "detected-fixture", items: [
      { source_key: "ready-fixture", name: "Synthetic", status: "ready", has_local_data: true },
      { source_key: "busy-fixture", name: "Synthetic busy", status: "source_open" },
    ] };
    if (action === "sync_windows") return { job_id: "fixture-job" };
    return syncStatus({ state: "completed", total: 1, completed: 1 });
  };
  h.element("#create-button").onclick();
  await new Promise(setImmediate);
  assert.deepEqual(calls.map((call) => call.action), ["sync_preview"]);
  assert.equal(h.state.sync.jobId, null);
  assert.match(h.element("#sync-preview-summary").textContent, /可导入 1 个/);
  assert.equal(h.element("#sync-start").textContent, "开始同步 1 个窗口");
  await h.context.startSync();
  await new Promise(setImmediate);
  assert.equal(calls.filter((call) => call.action === "sync_windows").length, 1);
  assert.equal(calls.find((call) => call.action === "sync_windows").payload.preview_id, "detected-fixture");
});

test("closing detection before its response never starts copying and redetection replaces the receipt", async () => {
  const h = fixture(), pending = deferred(), calls = [];
  h.context.api = async (action) => { calls.push(action); return pending.promise; };
  h.context.openSyncDialog({ autoStart: true });
  h.context.closeSyncDialog();
  pending.resolve({ preview_id: "first-fixture", items: [{ source_key: "ready-fixture", status: "ready" }] });
  await new Promise(setImmediate);
  assert.deepEqual(calls, ["sync_preview"]);
  assert.equal(h.state.sync.jobId, null);
  h.context.api = async () => ({ preview_id: "second-fixture", items: [] });
  await h.context.loadSyncPreview();
  assert.equal(h.state.sync.previewId, "second-fixture");
  assert.equal(h.state.sync.selected.size, 0);
  assert.equal(h.element("#sync-start").disabled, true);
});

test("missing or failed detection cannot reuse an older receipt or start copying", async () => {
  const h = fixture();
  h.state.sync.previewId = "old-fixture";
  h.context.api = async () => ({ items: [{ source_key: "ready-fixture", status: "ready" }] });
  await h.context.loadSyncPreview();
  assert.equal(h.state.sync.previewId, null);
  assert.equal(h.element("#sync-start").disabled, true);
  h.state.sync.preview = [{ source_key: "ready-fixture", status: "ready" }];
  h.state.sync.selected.add("ready-fixture");
  let calls = 0;
  h.context.api = async () => { calls++; };
  await h.context.startSync();
  assert.equal(calls, 0);
  assert.match(h.state.sync.error, /重新检测/);
});

test("10k candidates keep all rows available and cap each cross-page batch at 9999", async () => {
  const h = fixture();
  const candidates = Array.from({ length: 10000 }, (_, i) => ({
    source_key: `fixture-${i}`, name: `Window ${i}`, seq: i + 1,
    status: "ready", has_local_data: true,
  }));
  h.context.api = async () => ({ preview_id: "fixture-preview", items: [...candidates, candidates[0], null] });
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
  assert.equal(requests[0].payload.preview_id, "fixture-preview");
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
  h.context.api = async () => ({ preview_id: "fixture-preview", items: candidates.map((item) => ({
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
    if (action === "sync_preview") return ++previews === 1 ? oldPreview.promise : { preview_id: "fixture-preview", items: [{ source_key: "new-fixture", name: "New fixture", status: "ready" }] };
    return { deleted: true, cleanup_complete: true };
  };
  const old = h.context.loadSyncPreview();
  await h.context.performAction("delete", "fixture-0");
  assert.equal(previews, 2);
  oldPreview.resolve({ preview_id: "fixture-preview", items: [{ source_key: "old-fixture", name: "Old fixture", status: "already_imported" }] }); await old;
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
    return { preview_id: "fixture-preview", items: [{ source_key: "available-fixture", name: "Available fixture", status: "ready" }] };
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
    if (action === "sync_preview") { previews++; return { preview_id: "fixture-preview", items: [] }; }
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
    assert.equal(action, "sync_preview"); return { preview_id: "fixture-preview", items: [] };
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
    assert.equal(action, "sync_preview"); return { preview_id: "fixture-preview", items: [] };
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
    return { preview_id: "fixture-preview", items: [{ source_key: "available-fixture", status: "ready" }] };
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
    if (action === "sync_preview") { previews++; return { preview_id: "fixture-preview", items: [] }; }
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
    assert.equal(action, "sync_preview"); return { preview_id: "fixture-preview", items: [] };
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
