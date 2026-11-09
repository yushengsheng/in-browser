// Isolated execution of the installed version's selected configuration routines.
// Input/output are pipes consumed locally by prepare_two_windows.py, never console logs.
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

function functionSource(source, name) {
  const match = new RegExp('(?:async )?function ' + name + '\\(').exec(source);
  if (!match) throw new Error('Inspected function missing');
  for (let end = source.indexOf('}', match.index); end >= 0; end = source.indexOf('}', end + 1)) {
    const candidate = source.slice(match.index, end + 1);
    try { new vm.Script(candidate); return candidate; } catch (_) {}
  }
  throw new Error('Inspected function boundary unresolved');
}

function merge(target, source) {
  if (!source || typeof source !== 'object') return target;
  for (const [key, value] of Object.entries(source)) {
    if (['__proto__', 'constructor', 'prototype'].includes(key)) throw new Error('Unsafe merge key');
    if (value && typeof value === 'object') {
      if (!target[key] || typeof target[key] !== 'object') target[key] = Array.isArray(value) ? [] : {};
      merge(target[key], value);
    } else if (value !== undefined) target[key] = value;
  }
  return target;
}

async function main() {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const source = fs.readFileSync(input.sourceFile, 'utf8');
  const classStart = source.indexOf('us={6.3:');
  const classEnd = source.indexOf('async function ps(', classStart);
  if (classStart < 0 || classEnd < 0) throw new Error('Inspected class boundary missing');
  let captured;
  const logger = { info(){}, error(){}, warn(){} };
  const context = vm.createContext({
    c: { default: logger }, g: logger, ls: { fingerprint(){} },
    ve: { default: merge }, w: (value) => JSON.parse(value),
    zt: (min,max) => {
      if (input.rejectRandomization) throw new Error('Source fingerprint requires random regeneration');
      return crypto.randomInt(Math.ceil(min),Math.floor(max)+1);
    },
    process: Object.freeze({ platform: 'win32' }),
    t: { default: { screen: { getPrimaryDisplay: () => input.display } } },
    n: { default: { resolve: (...parts) => parts.join('/') } }, fj: () => 'local',
    So: async () => input.maxImageBypass || null,
    M: async () => input.permissions,
    uo: async () => input.employeeLimits || {},
    as: async (key = 'badge') => input.badges[key] || '',
    wa: async () => input.languages,
    Sa: async (code) => input.webgl[code] || {},
    Ao: async () => input.bypassRules || [], Co: async () => [],
    Xi: async ({fontType}) => +fontType===0 ? null : input.fontConfig,
    Ho: async () => input.variations || null,
    Vr: async () => input.touchColor || null,
    hs: async (_path, value) => { captured = JSON.parse(value); },
  });
  const code = 'var ' + source.slice(classStart, classEnd) + '\n' +
    ['gs', '_s', 'ca', 'os', 'ss', 'cs', 'ps'].map(name => functionSource(source, name)).join('\n');
  new vm.Script(code).runInContext(context, {timeout: 3000});
  context.info = input.info;
  context.geo = input.geo;
  await new vm.Script('ps(info, geo)').runInContext(context, {timeout: 3000});
  if (!captured || typeof captured !== 'object' || Array.isArray(captured)) throw new Error('Native configuration missing');
  const fp = input.info && input.info.browserFingerPrint || {};
  let extension = fp.extendOptions;
  if (typeof extension === 'string') extension = JSON.parse(extension);
  if (extension != null && (typeof extension !== 'object' || Array.isArray(extension))) throw new Error('Invalid protection options');
  const protection = extension && extension.DataProtect;
  const legacy = input.allowLegacyProtection === true && /^[0-9]{2,3}$/.test(String(fp.coreVersion)) && Number(fp.coreVersion) < 130;
  if (protection == null) {
    if (!legacy || captured.DataProtect != null) throw new Error('Unexpected protection configuration');
  } else {
    if (typeof protection !== 'object' || Array.isArray(protection) || typeof protection.CipherKey !== 'string' || !protection.CipherKey ||
        !isDeepStrictEqual(captured.DataProtect, protection)) throw new Error('Protection configuration changed');
  }
  process.stdout.write(JSON.stringify(captured));
}

main().catch(() => { process.stderr.write('Configuration transformation failed'); process.exitCode = 1; });
