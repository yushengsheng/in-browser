"""Bounded, local environment checks without opening an account profile.

This detects changes in sampled browser surfaces; it cannot freeze hardware or
prove that every signal visible to every site stays identical. Baselines belong
in the existing encrypted profile record and are never created by verification.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import time
import uuid

from browser_core import APP_ROOT, BrowserController, CDP, sha256
from browser_processes import profile_processes
from environment_compatibility import (compatibility_candidate, validated_environment_args,
                                       vendor_compatibility_policy, vendor_device_differences)
from local_state import LocalBrowserError
from native_paths import io_path, resolved_path


FORMAT = 1
PROBE_VERSION = 2
MAX_SNAPSHOT_BYTES = 1_000_000
MAX_BASELINE_FIELDS = 160
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_SAFE_SWITCHES = frozenset({
    '--force-device-scale-factor', '--high-dpi-support', '--lang', '--accept-lang',
    '--window-size', '--window-position', '--force-color-profile',
    '--disable-color-correct-rendering', '--enable-color-correct-rendering',
    '--enable-features', '--disable-features', '--disable-blink-features',
    '--use-angle', '--use-gl', '--disable-gpu', '--disable-gpu-compositing',
    '--disable-software-rasterizer', '--enable-unsafe-swiftshader',
    '--ignore-gpu-blocklist', '--no-sandbox', '--disable-dev-shm-usage',
})
_REQUIRED = frozenset({'navigator.userAgent', 'navigator.platform',
                       'navigator.languages', 'timezone.name',
                       'context.secure', 'uaData.supported', 'devices.supported',
                       'screen.width', 'screen.height', 'screen.devicePixelRatio',
                       'canvas.geometry', 'canvas.text', 'fonts.metrics',
                       'webgl1.supported', 'webgl2.supported', 'audio.supported'})
_REQUIRED_STABLE = _REQUIRED - {'canvas.geometry', 'canvas.text'}
_RASTER_FIELDS = frozenset({'canvas.geometry', 'canvas.text', 'webgl1.pixels', 'webgl2.pixels'})
_PIXELS = frozenset({'canvas.geometry', 'canvas.text', 'webgl1.pixels',
                     'webgl2.pixels', 'audio.offline'})
_FAILURE = '环境连续性检查未完成，未启动真实窗口；原资料和基线已保留。'
_STATIC_PAGE = b'<!doctype html><html><head><meta charset="utf-8"><title>Local environment check</title></head><body></body></html>'
_READY_EXPRESSION = '({ready:document.readyState,secure:isSecureContext,url:location.href})'
# These WebUI targets are Chromium's omnibox surface, not user tabs. They may
# be eagerly created by a signed field trial even with an initial blank tab.
_INTERNAL_PROBE_TARGETS=frozenset({'chrome://omnibox-popup.top-chrome/','chrome://omnibox-popup.top-chrome/omnibox_popup_aim.html'})


_FETCH_EVENTS = frozenset((
    'Page.frameStartedLoading', 'Page.frameStoppedLoading', 'Page.frameNavigated',
    'Page.domContentEventFired', 'Page.loadEventFired', 'Page.lifecycleEvent',
    'Runtime.executionContextCreated', 'Runtime.executionContextDestroyed',
    'Runtime.executionContextsCleared', 'Target.attachedToTarget', 'Target.targetInfoChanged'))


def _fetch_failure(reason):
    error = _blocked(['probe.navigation'])
    error.code = 'continuity_fetch_' + reason
    return error


def _probe_remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _fetch_failure('budget')
    return remaining


def _fulfill_probe_document(connection, session, frame_id, url, deadline):
    """Route only the owned document while retaining both command replies."""
    wire = connection.connection
    pending, requests = {}, set()
    navigation = None
    result = None
    fulfilled = acknowledged = 0
    rejected = False

    def send(method, params):
        wire.settimeout(min(8, _probe_remaining(deadline)))
        connection.next_id += 1
        identifier = connection.next_id
        wire.send(json.dumps({'id': identifier, 'method': method, 'params': params, 'sessionId': session}))
        pending[identifier] = method
        return identifier

    try:
        navigation = send('Page.navigate', {'url': url})
        for _ in range(128):
            wire.settimeout(min(8, _probe_remaining(deadline)))
            raw = wire.recv()
            if not isinstance(raw, (str, bytes)):
                raise _fetch_failure('message')
            try:
                if len(raw if isinstance(raw, bytes) else raw.encode('utf-8')) > 1_000_000:
                    raise _fetch_failure('message')
                message = json.loads(raw)
            except (ValueError, TypeError):
                raise _fetch_failure('message') from None
            if not isinstance(message, dict):
                raise _fetch_failure('message')
            if message.get('method') == 'Fetch.requestPaused':
                params = message.get('params')
                if not isinstance(params, dict):
                    raise _fetch_failure('request')
                request = params.get('request')
                request_id = params.get('requestId')
                if message.get('sessionId') != session:
                    raise _fetch_failure('session')
                if not isinstance(request_id, str) or not request_id or request_id in requests:
                    raise _fetch_failure('request_id')
                requests.add(request_id)
                valid = (isinstance(request, dict) and request.get('url') == url
                         and request.get('method') == 'GET' and params.get('frameId') == frame_id
                         and params.get('resourceType') == 'Document' and not params.get('redirectedRequestId')
                         and 'responseStatusCode' not in params and 'responseErrorReason' not in params
                         and fulfilled < 2)
                if not valid:
                    send('Fetch.failRequest', {'requestId': request_id, 'errorReason': 'BlockedByClient'})
                    rejected = True
                    continue
                send('Fetch.fulfillRequest', {'requestId': request_id, 'responseCode': 200,
                    'responseHeaders': [
                        {'name': 'Content-Type', 'value': 'text/html; charset=utf-8'},
                        {'name': 'Content-Length', 'value': str(len(_STATIC_PAGE))},
                        {'name': 'Connection', 'value': 'close'},
                        {'name': 'Cache-Control', 'value': 'no-store'},
                        {'name': 'X-Content-Type-Options', 'value': 'nosniff'},
                        {'name': 'Referrer-Policy', 'value': 'no-referrer'},
                        {'name': 'Content-Security-Policy', 'value': "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}],
                    'body': base64.b64encode(_STATIC_PAGE).decode('ascii')})
                fulfilled += 1
            elif 'id' in message:
                identifier = message['id']
                if (type(identifier) is not int or identifier not in pending
                        or message.get('sessionId', session) != session):
                    raise _fetch_failure('reply_id')
                method = pending.pop(identifier)
                if 'error' in message:
                    raise _fetch_failure('protocol')
                reply = message.get('result', {})
                if not isinstance(reply, dict):
                    raise _fetch_failure('reply')
                if identifier == navigation:
                    if rejected:
                        continue
                    if reply.get('errorText') or reply.get('isDownload'):
                        raise _fetch_failure('navigation')
                    if (reply.get('frameId') != frame_id or not isinstance(reply.get('loaderId'), str)
                            or not reply['loaderId']):
                        raise _fetch_failure('document')
                    result = reply
                elif method == 'Fetch.fulfillRequest':
                    acknowledged += 1
                elif method == 'Fetch.failRequest':
                    raise _fetch_failure('request')
                else:
                    raise _fetch_failure('reply_id')
            elif (message.get('method') not in _FETCH_EVENTS
                    or message.get('sessionId', session) != session):
                raise _fetch_failure('event')
            if result is not None and fulfilled == acknowledged and fulfilled and not pending:
                _probe_remaining(deadline)
                return result
        raise _fetch_failure('event_limit')
    except LocalBrowserError:
        raise
    except Exception:
        raise _fetch_failure('transport') from None


def _navigate_local_page(connection, session, url):
    """Fulfill a fixed secure document; never fall back to real HTTP content."""
    deadline = time.monotonic() + 5
    original_timeout = connection.timeout

    def call(method, params=None):
        connection.timeout = min(original_timeout, _probe_remaining(deadline))
        connection.connection.settimeout(min(8, connection.timeout))
        return connection.call(method, params, session=session)

    def main_frame(reply):
        branch = reply.get('frameTree') if isinstance(reply, dict) else None
        frame = branch.get('frame') if isinstance(branch, dict) else None
        if not isinstance(frame, dict):
            raise _fetch_failure('document')
        return frame

    try:
        if not isinstance(url, str) or not re.fullmatch(r'https://probe\.invalid/[0-9a-f]{32}', url):
            raise _fetch_failure('document')
        frame = main_frame(call('Page.getFrameTree'))
        if (frame.get('url') != 'about:blank' or frame.get('unreachableUrl')
                or not isinstance(frame.get('id'), str) or not frame['id']):
            raise _fetch_failure('document')
        call('Fetch.enable', {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]})
        result = _fulfill_probe_document(connection, session, frame['id'], url, deadline)
        # Disable only after fulfillment and navigation acknowledgements. On
        # failure the original empty-profile shutdown runs without sampling.
        call('Fetch.disable')
        while True:
            reply = call('Runtime.evaluate', {'expression': _READY_EXPRESSION, 'returnByValue': True})
            if not isinstance(reply, dict) or reply.get('exceptionDetails'):
                raise _fetch_failure('document')
            ready = reply.get('result', {}).get('value')
            if (isinstance(ready, dict) and ready.get('url') == url
                    and ready.get('ready') == 'complete' and ready.get('secure') is True):
                current = main_frame(call('Page.getFrameTree'))
                if (current.get('id') != frame['id'] or current.get('loaderId') != result['loaderId']
                        or current.get('url') != url or current.get('unreachableUrl')):
                    raise _fetch_failure('document')
                _probe_remaining(deadline)
                return
            time.sleep(min(.05, _probe_remaining(deadline)))
    finally:
        connection.timeout = original_timeout


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def _same_value(first, second):
    # Python considers True == 1; browser JSON types must remain distinct.
    try:
        return _json(first) == _json(second)
    except (ValueError, TypeError, OverflowError):
        return False


def _safe_field(field):
    return isinstance(field, str) and bool(re.fullmatch(r'[A-Za-z][A-Za-z0-9_.]{0,79}', field))


def _blocked(fields, *, environment_args=None):
    safe = sorted({field for field in fields if _safe_field(field)})
    names = '、'.join(safe[:16]) or 'probe'
    categories = []
    for prefix, category in (('fonts.', '字体'), ('canvas.', '绘图'),
                             ('webgl', '绘图'), ('audio.', '音视频设备'),
                             ('devices.', '音视频设备'), ('screen.', '显示偏好')):
        if any(field.startswith(prefix) for field in safe) and category not in categories:
            categories.append(category)
    detail = '；涉及' + '、'.join(categories) if categories else ''
    error = LocalBrowserError('环境连续性检查未通过（' + names + detail + '），未启动真实窗口；原资料和基线已保留。')
    error.changed_fields = safe
    error.environment_args = validated_environment_args({'environment_args': environment_args or []})
    return error


def _launch_arguments(runtime):
    result = []
    for arg in runtime.get('launch_args') or []:
        if not isinstance(arg, str) or '\x00' in arg or '\r' in arg or '\n' in arg:
            raise _blocked(['launch_args'])
        switch = arg.split('=', 1)[0].lower()
        created_certificate_option=(runtime.get('creation_options_version')==1 and arg=='--ignore-certificate-errors')
        if switch not in _SAFE_SWITCHES and not created_certificate_option:
            # An unknown argument can load a website, extension or alternative
            # resource. Do not silently drop it and compare a different setup.
            raise _blocked(['launch_args'])
        result.append(arg)
    return result


def native_digest(native, root=None):
    """Bind fingerprint payload, excluding three unrelated preference outputs."""
    if not isinstance(native, dict):
        raise _blocked(['native'])
    value = copy.deepcopy(native)
    for preference in ('MemorySaverModeEnabled', 'maxImageBytes', 'notificationsMode'):
        value.pop(preference, None)
    font = value.get('FontConfig')
    if isinstance(font, dict):
        if font.get('Files') not in (None, []):
            raise _blocked(['FontConfig.Files'])
        path = font.get('BasePath')
        if isinstance(path, str) and path:
            for token, base in ([('@data/', Path(root).resolve())] if root is not None else []) + [('@app/', APP_ROOT.resolve())]:
                try:
                    relative = Path(path).resolve().relative_to(base)
                except (OSError, ValueError):
                    continue
                font['BasePath'] = token + relative.as_posix()
                break
    return _digest(value)


def _engine_binding(runtime):
    executable = resolved_path(runtime['core_path'])
    actual = sha256(executable)
    if actual != runtime.get('core_sha256'):
        raise _blocked(['core'])
    manifest = executable.parent / 'manifest.json'
    if not io_path(manifest).is_file() or io_path(manifest).stat().st_size > _MAX_MANIFEST_BYTES:
        raise _blocked(['core.manifest'])
    data = json.loads(io_path(manifest).read_text(encoding='utf-8'))
    files = data.get('files')
    if (not isinstance(files, dict) or not files or data.get('format') != 1
            or str(data.get('core_major')) != str(runtime.get('core_major'))
            or data.get('executable') != executable.name):
        raise _blocked(['core.manifest'])
    names = [name for name in files if isinstance(name, str) and PurePosixPath(name.replace('\\', '/')).name.casefold() == 'chrome.dll']
    if len(names) != 1:
        raise _blocked(['core.chrome'])
    relative = PurePosixPath(names[0].replace('\\', '/'))
    if relative.is_absolute() or '..' in relative.parts or any(':' in part for part in relative.parts):
        raise _blocked(['core.manifest'])
    chrome = resolved_path(executable.parent.joinpath(*relative.parts))
    if not chrome.is_relative_to(executable.parent):
        raise _blocked(['core.manifest'])
    from engine_validation import digest_file
    dll_hash = digest_file(chrome)
    if dll_hash != (files[names[0]] or {}).get('sha256'):
        raise _blocked(['core.chrome'])
    # Existing engine validation remains authoritative for the complete tree.
    # Binding its manifest also covers resources other than the executable/DLL.
    from local_engine import continuity_manifest
    return {'executable': actual, 'chrome': dll_hash, 'manifest': _digest(continuity_manifest(data,executable))}


def binding_for(record, root=None):
    """Return portable identities; no credentials, addresses or paths are stored."""
    try:
        runtime = record['_runtime']
        args = _launch_arguments(runtime)
        return {'profile': _digest(str(record['id'])),
                'native': native_digest(record['_native'], root),
                'engine': _engine_binding(runtime),
                'core_major': str(runtime['core_major']),
                'launch': _digest({'args': args, 'language': runtime.get('language', ''),
                                   'disable_gpu': bool(runtime.get('disable_gpu'))}),
                'probe_version': PROBE_VERSION}
    except LocalBrowserError:
        raise
    except Exception:
        raise _blocked(['binding']) from None


def _font_names(record):
    names = ['Arial', 'Times New Roman', 'Courier New', 'Segoe UI',
             'Microsoft YaHei', 'SimSun', 'sans-serif', 'serif', 'monospace']
    font = record.get('_native', {}).get('FontConfig') or {}
    configured = font.get('Names') or []
    if not isinstance(configured, list):
        raise _blocked(['FontConfig.Names'])
    for name in configured:
        if not isinstance(name, str) or len(name) > 200:
            raise _blocked(['FontConfig.Names'])
        names.extend(part.strip() for part in name.split(';') if part.strip())
    # Keep every configured family within a finite probe. Do not silently sample
    # only the first part of an unexpectedly large configuration.
    names = list(dict.fromkeys(names))
    if len(names) > 128:
        raise _blocked(['FontConfig.Names'])
    return names


_EXPRESSION = r"""(async () => {
  'use strict';
  document.title = '环境检查（可关闭）';
  const values = {}, errors = [], unavailable = [];
  const unsupported = {status: 'unsupported'};
  const put = (key, value) => { values[key] = value === undefined ? unsupported : value; };
  const sync = (key, fn) => { try { put(key, fn()); } catch (_) { errors.push(key); } };
  const bounded = async (key, fn, limit=1000) => {
    let timer;
    try {
      const value = await Promise.resolve().then(() => {
        const deadline = new Promise((_, reject) => { timer=setTimeout(() => reject(new Error()), limit); });
        return Promise.race([fn(), deadline]);
      });
      put(key, value);
    } catch (_) { errors.push(key); }
    finally { clearTimeout(timer); }
  };
  const bytes = data => {
    let raw='';
    for (let i=0; i<data.length; i+=8192) raw += String.fromCharCode(...data.subarray(i, i+8192));
    return 'base64:' + btoa(raw);
  };
  for (const key of ['userAgent','platform','vendor','hardwareConcurrency','deviceMemory',
                      'maxTouchPoints','language','languages','webdriver','cookieEnabled'])
    sync('navigator.'+key, () => navigator[key]);
  sync('context.secure', () => isSecureContext);
  sync('timezone.name', () => Intl.DateTimeFormat().resolvedOptions().timeZone);
  sync('locale.options', () => Intl.DateTimeFormat().resolvedOptions());
  for (const key of ['width','height','availWidth','availHeight','colorDepth','pixelDepth'])
    sync('screen.'+key, () => screen[key]);
  sync('screen.devicePixelRatio', () => devicePixelRatio);
  sync('screen.orientation', () => screen.orientation ? {type:screen.orientation.type,angle:screen.orientation.angle} : unsupported);
  sync('screen.media', () => Object.fromEntries(['(color-gamut: srgb)','(color-gamut: p3)',
    '(color-gamut: rec2020)','(dynamic-range: high)','(pointer: fine)','(hover: hover)',
    '(prefers-color-scheme: dark)','(prefers-reduced-motion: reduce)'].map(q => [q,matchMedia(q).matches])));
  const jobs=[];
  if (navigator.userAgentData) {
    put('uaData.supported',true);
    sync('uaData.low', () => navigator.userAgentData.toJSON());
    jobs.push(bounded('uaData.high', () => navigator.userAgentData.getHighEntropyValues([
      'architecture','bitness','model','platformVersion','uaFullVersion','fullVersionList','wow64','formFactors'])));
  } else { put('uaData.supported',false); unavailable.push('uaData'); }
  for (const text of [false,true]) {
    const name = text ? 'canvas.text' : 'canvas.geometry';
    sync(name, () => {
      const c=document.createElement('canvas'); c.width=240; c.height=80;
      const x=c.getContext('2d'); if (!x) throw new Error();
      x.fillStyle='#edc'; x.fillRect(0,0,240,80);
      const gradient=x.createLinearGradient(0,0,240,80); gradient.addColorStop(0,'#173'); gradient.addColorStop(1,'#c38');
      x.fillStyle=gradient; x.beginPath(); x.arc(42,39,27,0,Math.PI*1.8); x.fill();
      x.globalCompositeOperation='multiply'; x.fillStyle='rgba(20,90,180,0.63)'; x.fillRect(28,15,93,46);
      x.globalCompositeOperation='source-over';
      if (text) { x.font='19px Arial'; x.textBaseline='alphabetic'; x.fillStyle='#264'; x.fillText('Continuity W0Il 中文汉字',3,62); }
      return bytes(x.getImageData(0,0,240,80).data);
    });
  }
  sync('fonts.metrics', () => {
    const canvas=document.createElement('canvas'), x=canvas.getContext('2d'); if (!x) throw new Error();
    const text='mmmmmmmmmmlliW0O 中文汉字';
    return FONT_NAMES.map(name => [name, ...['monospace','sans-serif','serif'].map(base => {
      x.font='72px '+JSON.stringify(name)+','+base;
      const m=x.measureText(text);
      return [m.width,m.actualBoundingBoxAscent,m.actualBoundingBoxDescent,
        m.actualBoundingBoxLeft,m.actualBoundingBoxRight].map(v => Number.isFinite(v) ? v : null);
    })]);
  });
  for (const kind of ['webgl','webgl2']) {
    const prefix=kind==='webgl' ? 'webgl1' : 'webgl2';
    let gl=null, program=null, buffer=null, shaders=[];
    try {
      const c=document.createElement('canvas'); c.width=32; c.height=32;
      gl=c.getContext(kind,{antialias:false,alpha:false,depth:false,stencil:false,preserveDrawingBuffer:true});
      put(prefix+'.supported',Boolean(gl));
      if (!gl) { unavailable.push(prefix); continue; }
      const dbg=gl.getExtension('WEBGL_debug_renderer_info');
      put(prefix+'.identity',{vendor:gl.getParameter(gl.VENDOR),renderer:gl.getParameter(gl.RENDERER),
        version:gl.getParameter(gl.VERSION),shadingLanguage:gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        unmaskedVendor:dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : unsupported,
        unmaskedRenderer:dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : unsupported});
      put(prefix+'.extensions',(gl.getSupportedExtensions() || []).slice().sort());
      const caps={};
      for (const key of ['MAX_TEXTURE_SIZE','MAX_CUBE_MAP_TEXTURE_SIZE','MAX_RENDERBUFFER_SIZE','MAX_VIEWPORT_DIMS',
        'MAX_VERTEX_ATTRIBS','MAX_VERTEX_UNIFORM_VECTORS','MAX_FRAGMENT_UNIFORM_VECTORS','MAX_VARYING_VECTORS',
        'MAX_TEXTURE_IMAGE_UNITS','MAX_VERTEX_TEXTURE_IMAGE_UNITS','MAX_COMBINED_TEXTURE_IMAGE_UNITS']) {
        const v=gl.getParameter(gl[key]); caps[key]=ArrayBuffer.isView(v) ? Array.from(v) : v;
      }
      put(prefix+'.limits',caps);
      const precision={};
      for (const stage of ['VERTEX_SHADER','FRAGMENT_SHADER'])
        for (const p of ['LOW_FLOAT','MEDIUM_FLOAT','HIGH_FLOAT','LOW_INT','MEDIUM_INT','HIGH_INT']) {
          const f=gl.getShaderPrecisionFormat(gl[stage],gl[p]);
          precision[stage+'.'+p]=f ? [f.rangeMin,f.rangeMax,f.precision] : null;
        }
      put(prefix+'.precision',precision); put(prefix+'.attributes',gl.getContextAttributes());
      const vertex='attribute vec2 p; varying vec2 v; void main(){v=p;gl_Position=vec4(p,0.0,1.0);}';
      const fragment='precision highp float; varying vec2 v; void main(){gl_FragColor=vec4(sin(v.x*2.7)*0.5+0.5,cos(v.y*3.1)*0.5+0.5,v.x*v.y*0.25+0.5,1.0);}';
      program=gl.createProgram();
      for (const [type,source] of [[gl.VERTEX_SHADER,vertex],[gl.FRAGMENT_SHADER,fragment]]) {
        const s=gl.createShader(type); shaders.push(s); gl.shaderSource(s,source); gl.compileShader(s);
        if (!gl.getShaderParameter(s,gl.COMPILE_STATUS)) throw new Error();
        gl.attachShader(program,s);
      }
      gl.linkProgram(program); if (!gl.getProgramParameter(program,gl.LINK_STATUS)) throw new Error();
      gl.useProgram(program); buffer=gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER,buffer);
      gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,1,1]),gl.STATIC_DRAW);
      const location=gl.getAttribLocation(program,'p'); gl.enableVertexAttribArray(location);
      gl.vertexAttribPointer(location,2,gl.FLOAT,false,0,0); gl.viewport(0,0,32,32);
      gl.drawArrays(gl.TRIANGLE_STRIP,0,4);
      const pixels=new Uint8Array(32*32*4); gl.readPixels(0,0,32,32,gl.RGBA,gl.UNSIGNED_BYTE,pixels);
      if (gl.isContextLost() || gl.getError()!==gl.NO_ERROR) throw new Error();
      put(prefix+'.pixels',bytes(pixels));
    } catch (_) { errors.push(prefix); }
    finally {
      if (gl) {
        if (buffer) gl.deleteBuffer(buffer); if (program) gl.deleteProgram(program);
        for (const shader of shaders) gl.deleteShader(shader);
        const lose=gl.getExtension('WEBGL_lose_context'); if (lose) lose.loseContext();
      }
    }
  }
  const Offline=window.OfflineAudioContext || window.webkitOfflineAudioContext;
  put('audio.supported',Boolean(Offline));
  if (Offline) jobs.push(bounded('audio.offline',async () => {
    const context=new Offline(1,4096,44100), oscillator=context.createOscillator(), compressor=context.createDynamicsCompressor();
    try {
      oscillator.type='triangle'; oscillator.frequency.value=10000;
      compressor.threshold.value=-50; compressor.knee.value=40; compressor.ratio.value=12;
      compressor.attack.value=0; compressor.release.value=0.25;
      oscillator.connect(compressor); compressor.connect(context.destination); oscillator.start(0);
      const output=(await context.startRendering()).getChannelData(0), raw=new Uint8Array(output.length*4), view=new DataView(raw.buffer);
      for (let i=0;i<output.length;i++) { if (!Number.isFinite(output[i])) throw new Error(); view.setFloat32(i*4,output[i],true); }
      return bytes(raw);
    } finally { oscillator.disconnect(); compressor.disconnect(); }
  }));
  else unavailable.push('audio');
  if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    put('devices.supported',true);
    jobs.push(bounded('devices.kinds', async () => {
      try {
        const kinds={audioinput:0,audiooutput:0,videoinput:0};
        for (const device of await navigator.mediaDevices.enumerateDevices())
          if (Object.prototype.hasOwnProperty.call(kinds,device.kind)) kinds[device.kind]++;
        return kinds;
      }
      catch (_) { unavailable.push('devices'); return {status:'unavailable'}; }
    },3000));
  }
  else { put('devices.supported',false); unavailable.push('devices'); }
  await Promise.all(jobs);
  return {values,errors,unavailable};
})()"""


def _normalize_sample(sample):
    if not isinstance(sample, dict) or not isinstance(sample.get('values'), dict):
        raise _blocked(['probe'])
    if len(_json(sample)) > MAX_SNAPSHOT_BYTES or len(sample['values']) > MAX_BASELINE_FIELDS:
        raise _blocked(['probe'])
    if sample.get('errors'):
        raise _blocked(sample['errors'])
    values = sample['values']
    if any(not _safe_field(key) for key in values):
        raise _blocked(['probe'])
    for key in _PIXELS & values.keys():
        raw = values[key]
        if not isinstance(raw, str) or not raw.startswith('base64:'):
            raise _blocked([key])
        decoded = base64.b64decode(raw[7:], validate=True)
        if not decoded or len(decoded) > 240 * 80 * 4:
            raise _blocked([key])
        values[key] = 'sha256:' + hashlib.sha256(decoded).hexdigest()
    if not _REQUIRED <= values.keys():
        raise _blocked(_REQUIRED - values.keys())
    if values['context.secure'] is not True:
        raise _blocked(['probe.secureContext'])
    for key in ('uaData.supported', 'devices.supported'):
        if not isinstance(values[key], bool):
            raise _blocked([key])
    if values['uaData.supported'] and not {'uaData.low', 'uaData.high'} <= values.keys():
        raise _blocked(['uaData'])
    if values['devices.supported'] and 'devices.kinds' not in values:
        raise _blocked(['devices'])
    return {'values': values, 'unavailable': sorted(set(sample.get('unavailable') or []))}


def _blank_target(connection):
    """The debug socket can be ready before Chromium finishes its blank tab."""
    deadline=time.monotonic()+5
    original_timeout=connection.timeout
    try:
        while time.monotonic()<deadline:
            connection.timeout=min(original_timeout,max(.01,deadline-time.monotonic()))
            targets=connection.call('Target.getTargets').get('targetInfos',[])
            pages=[target for target in targets if target.get('type')=='page' and target.get('url') not in _INTERNAL_PROBE_TARGETS]
            if any(target.get('url') not in ('','about:blank') for target in pages):
                raise _blocked(['probe.target'])
            if pages and all(target.get('url')=='about:blank' for target in pages):return pages[0]['targetId']
            time.sleep(min(.05,max(0,deadline-time.monotonic())))
        raise _blocked(['probe.target'])
    finally:connection.timeout=original_timeout


def _merge_samples(first, second):
    a, b = first['values'], second['values']
    unstable = sorted(key for key in a.keys() | b.keys()
                      if key not in a or key not in b or not _same_value(a[key], b[key]))
    return {'values': {key: value for key, value in a.items() if key not in unstable},
            'unstable': unstable,
            'unavailable': sorted(set(first.get('unavailable', [])) | set(second.get('unavailable', [])))}


def probe_snapshot(record, root):
    """Two reads on one owned secure page; never copy account profile data."""
    temporary = None
    controller = None
    profile = None
    desktop = None
    result = None
    try:
        root = Path(root).resolve()
        args = _launch_arguments(record['_runtime'])
        names = _font_names(record)
        temporary = Path(tempfile.mkdtemp(prefix='continuity-probe-', dir=root)).resolve()
        if temporary.parent != root:
            raise _blocked(['probe'])
        profile = temporary / 'profile'
        profile.mkdir()
        runtime = copy.deepcopy(record['_runtime'])
        runtime.update(alias='probe_' + uuid.uuid4().hex, profile_path=str(profile),
                       new_profile=True, has_launched=False, restore_session=False,
                       initial_urls=[], open_urls_once=[], launch_args=args,
                       account_platform='', account_username='', account_password='')
        for key in ('managed_extension', 'local_proxy_mode', 'local_proxy_port'):
            runtime.pop(key, None)
        controller = BrowserController(temporary, settings={'windows': [runtime], 'persistent': False})
        # Keep all state in the temporary directory. Only signature verification
        # needs the actual encryption/signing root, which is never copied.
        controller.root = root
        local_url = 'https://probe.invalid/' + uuid.uuid4().hex
        presentation={}
        if str(runtime.get('core_major'))=='104':
            from probe_display import ProbeDesktop
            desktop=ProbeDesktop();presentation['background_desktop']=desktop
        controller.open(runtime['alias'], offline_test=True, extra_urls=['about:blank'], bootstrap_blank=True, background_probe=True,**presentation)
        expression = _EXPRESSION.replace('FONT_NAMES', json.dumps(names, ensure_ascii=False))
        with CDP(controller.endpoint(runtime['alias']), timeout=5) as connection:
            target=_blank_target(connection)
            session = connection.call('Target.attachToTarget', {'targetId': target, 'flatten': True})['sessionId']
            _navigate_local_page(connection, session, local_url)
            samples = []
            for _ in range(2):
                reply = connection.call('Runtime.evaluate', {'expression': expression, 'awaitPromise': True,
                                        'returnByValue': True}, session=session)
                if reply.get('exceptionDetails'):
                    raise _blocked(['probe.evaluate'])
                samples.append(_normalize_sample(reply.get('result', {}).get('value')))
            result = _merge_samples(*samples)
    except LocalBrowserError as exc:
        if str(exc).startswith('环境连续性检查') or getattr(exc,'code',None) in {
                'engine_path_too_long','profile_path_too_long','profile_path_invalid','profile_path_changed','profile_tree_limit'}:
            raise
        raise LocalBrowserError(_FAILURE) from None
    except Exception:
        raise LocalBrowserError(_FAILURE) from None
    finally:
        cleanup_ok = True
        if controller is not None:
            try:
                controller.close(next(iter(controller.profiles)))
            except Exception:
                cleanup_ok = False
        if profile is not None:
            try:
                if profile_processes(profile, require_inspectable=True):
                    cleanup_ok = False
            except Exception:
                cleanup_ok = False
        if desktop is not None:
            try:desktop.close()
            except Exception:cleanup_ok=False
        if temporary is not None and cleanup_ok:
            try:
                if (temporary.parent != Path(root).resolve() or not temporary.name.startswith('continuity-probe-')
                        or temporary.is_symlink() or temporary.resolve() != temporary):
                    cleanup_ok = False
                else:
                    shutil.rmtree(io_path(temporary))
            except OSError:
                cleanup_ok = False
        if not cleanup_ok:
            # Never kill a browser, delete live data, or silently accumulate
            # sessions after a hung/blocked normal close.
            raise LocalBrowserError('后台环境验证未能正常退出或清理，检查资料已保留，本次操作已停止；请保留程序目录，重启电脑后再试。') from None
    if result is None:
        raise LocalBrowserError(_FAILURE)
    return result


def create_baseline(record, root, *, progress=None):
    """Explicit source-machine enrollment; caller persists the encrypted record."""
    before = binding_for(record, root)
    if progress:
        progress('first')
    first = probe_snapshot(record, root)
    if progress:
        progress('second')
    second = probe_snapshot(record, root)
    merged = _merge_samples(first, second)
    unstable = sorted(set(merged['unstable']) | set(first.get('unstable', [])) | set(second.get('unstable', [])))
    stable = {key: value for key, value in merged['values'].items() if key not in unstable}
    if not _REQUIRED_STABLE <= stable.keys() or not _RASTER_FIELDS & stable.keys():
        raise _blocked(['probe.stability'])
    if binding_for(record, root) != before:
        raise _blocked(['binding'])
    return {'format': FORMAT, 'probe_version': PROBE_VERSION,
            'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'binding': before, 'stable': stable, 'unstable': unstable,
            'unavailable': merged['unavailable']}


def verify_continuity(record, root, *, allow_device_variance=False):
    """Keep strict enrollment; normal opens may accept bounded device variations."""
    baseline = record.get('_continuity')
    if not isinstance(baseline, dict) or baseline.get('format') != FORMAT or baseline.get('probe_version') != PROBE_VERSION:
        raise _blocked(['baseline'])
    stable = baseline.get('stable')
    unstable = baseline.get('unstable')
    if (not isinstance(stable, dict) or not stable or len(stable) > MAX_BASELINE_FIELDS
            or any(not _safe_field(k) for k in stable) or not isinstance(unstable, list)
            or any(not _safe_field(k) for k in unstable)
            or not _REQUIRED <= stable.keys() | set(unstable)
            or not _REQUIRED_STABLE <= stable.keys() or not _RASTER_FIELDS & stable.keys()):
        raise _blocked(['baseline'])
    try:
        if len(_json(baseline)) > MAX_SNAPSHOT_BYTES:
            raise _blocked(['baseline'])
    except (ValueError, TypeError):
        raise _blocked(['baseline']) from None
    current = binding_for(record, root)
    if baseline.get('binding') != current:
        raise _blocked(['binding'])

    # A previous run's choice is not evidence for this run. Always measure the
    # original environment first, without changing the persisted record.
    probe_record = copy.deepcopy(record)
    probe_record['_runtime']['environment_args'] = []
    actual = probe_snapshot(probe_record, root)
    if binding_for(record, root) != current:
        raise _blocked(['binding'])
    missing_or_unstable = [key for key in stable
                           if key not in actual['values'] or key in actual.get('unstable', [])]
    if missing_or_unstable:
        raise _blocked(missing_or_unstable)
    changes = [key for key, value in stable.items() if not _same_value(actual['values'][key], value)]
    accepted = (vendor_device_differences(record['_runtime'], stable, actual['values'])
                if allow_device_variance is True else [])
    environment_args = []
    if set(changes) - set(accepted):
        environment_args = compatibility_candidate(stable, changes)
        if not environment_args:
            raise _blocked(changes)
        probe_record['_runtime']['environment_args'] = environment_args
        actual = probe_snapshot(probe_record, root)
        if binding_for(record, root) != current:
            raise _blocked(['binding'], environment_args=environment_args)
        missing_or_unstable = [key for key in stable
                               if key not in actual['values'] or key in actual.get('unstable', [])]
        if missing_or_unstable:
            raise _blocked(missing_or_unstable, environment_args=environment_args)
        changes = [key for key, value in stable.items() if not _same_value(actual['values'][key], value)]
        accepted = (vendor_device_differences(record['_runtime'], stable, actual['values'])
                    if allow_device_variance is True else [])
        if set(changes) - set(accepted):
            raise _blocked(changes, environment_args=environment_args)
    return {'passed': True, 'stable_fields': len(stable),
            'unstable_fields': list(baseline.get('unstable') or []),
            'unavailable_fields': list(baseline.get('unavailable') or []),
            'environment_args': environment_args,
            'device_variance_fields': accepted,
             'verification_policy': (vendor_compatibility_policy(record['_runtime'])
                                     if allow_device_variance is True else 'strict')}
