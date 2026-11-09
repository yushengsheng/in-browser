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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import tempfile
import threading
import time
import uuid

from browser_core import APP_ROOT, BrowserController, CDP, sha256
from browser_processes import profile_processes
from local_state import LocalBrowserError


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


class _ProbePageHandler(BaseHTTPRequestHandler):
    """Only one owned URL is served; requests cannot supply content or paths."""
    protocol_version = 'HTTP/1.0'

    def log_message(self, *_):
        pass

    def version_string(self):
        return 'LocalProbe'

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler's default error page reflects request input.
        self._reply(code)

    def _reply(self, status, body=b'', *, head=False):
        self.close_connection = True
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        if not head and body:
            self.wfile.write(body)

    def _serve(self, *, head=False):
        hosts = self.headers.get_all('Host') or []
        expected = 'localhost:' + str(self.server.server_port)
        if len(hosts) != 1 or hosts[0].casefold() != expected:
            self._reply(400)
        elif self.headers.get('Transfer-Encoding') is not None or self.headers.get('Content-Length') not in (None, '0'):
            self._reply(400)
        elif self.path != self.server.probe_path:
            self._reply(404)
        else:
            self._reply(200, _STATIC_PAGE, head=head)

    def do_GET(self):
        self._serve()

    def do_HEAD(self):
        self._serve(head=True)

    def _reject(self):
        self._reply(405)

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_CONNECT = do_TRACE = _reject


class _ProbeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 4

    def __init__(self, address, handler):
        self._slots = threading.BoundedSemaphore(4)
        self._workers_lock = threading.Lock()
        self._workers = {}
        super().__init__(address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(1)
        return request, address

    def handle_error(self, *_):
        pass

    def process_request(self, request, address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        worker = threading.Thread(target=self._process_owned_request, args=(request, address),
                                  name='continuity-http-request', daemon=True)
        with self._workers_lock:
            self._workers[worker] = request
        try:
            worker.start()
        except Exception:
            with self._workers_lock:
                self._workers.pop(worker, None)
            self._slots.release()
            self.shutdown_request(request)
            raise

    def _process_owned_request(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            with self._workers_lock:
                self._workers.pop(threading.current_thread(), None)
            self._slots.release()

    def close_workers(self):
        with self._workers_lock:
            owned = list(self._workers.items())
        # Interrupt only sockets accepted by this short-lived server. Socket
        # timeouts and a bounded join also cover clients that send slowly.
        for _, request in owned:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass
        deadline = time.monotonic() + 1
        for worker, _ in owned:
            worker.join(timeout=max(0, deadline - time.monotonic()))
        return not any(worker.is_alive() for worker, _ in owned)


class _LoopbackPage:
    def __init__(self):
        self.server = None
        self.thread = None
        self.started = False

    def start(self):
        try:
            if self.server is not None:
                raise _blocked(['probe.server'])
            self.server = _ProbeHTTPServer(('127.0.0.1', 0), _ProbePageHandler)
            self.server.probe_path = '/' + uuid.uuid4().hex
            self.thread = threading.Thread(target=self.server.serve_forever,
                                           kwargs={'poll_interval': .05},
                                           name='continuity-http', daemon=True)
            self.thread.start()
            self.started = True
            return 'http://localhost:' + str(self.server.server_port) + self.server.probe_path
        except Exception:
            self.close()
            raise _blocked(['probe.server']) from None

    def close(self):
        if self.server is None:
            return
        okay = True
        try:
            if self.started and self.thread.is_alive():
                self.server.shutdown()
        except Exception:
            okay = False
        try:
            self.server.server_close()
        except Exception:
            okay = False
        if self.started:
            self.thread.join(timeout=1)
            if self.thread.is_alive():
                okay = False
        if not self.server.close_workers():
            okay = False
        if not okay:
            raise _blocked(['probe.server'])
        self.server = self.thread = None
        self.started = False


def _navigate_local_page(connection, session, url):
    """No fallback to an insecure or error page, even when APIs are absent."""
    deadline = time.monotonic() + 5
    original_timeout = connection.timeout
    try:
        connection.timeout = 5
        reply = connection.call('Page.navigate', {'url': url}, session=session)
        if reply.get('errorText'):
            raise _blocked(['probe.navigation'])
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _blocked(['probe.secureContext'])
            connection.timeout = min(original_timeout, remaining)
            reply = connection.call('Runtime.evaluate', {'expression': _READY_EXPRESSION,
                                    'returnByValue': True}, session=session)
            if reply.get('exceptionDetails'):
                raise _blocked(['probe.secureContext'])
            ready = reply.get('result', {}).get('value')
            if isinstance(ready, dict) and ready.get('url') == url and ready.get('ready') == 'complete' and ready.get('secure') is True:
                return
            time.sleep(min(.05, max(0, deadline - time.monotonic())))
    finally:
        connection.timeout = original_timeout


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def _safe_field(field):
    return isinstance(field, str) and bool(re.fullmatch(r'[A-Za-z][A-Za-z0-9_.]{0,79}', field))


def _blocked(fields):
    safe = sorted({field for field in fields if _safe_field(field)})
    names = '、'.join(safe[:16]) or 'probe'
    return LocalBrowserError('环境连续性检查未通过（' + names + '），未启动真实窗口；原资料和基线已保留。')


def _launch_arguments(runtime):
    result = []
    for arg in runtime.get('launch_args') or []:
        if not isinstance(arg, str) or '\x00' in arg or '\r' in arg or '\n' in arg:
            raise _blocked(['launch_args'])
        switch = arg.split('=', 1)[0].lower()
        if switch not in _SAFE_SWITCHES:
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
    executable = Path(runtime['core_path']).resolve()
    actual = sha256(executable)
    if actual != runtime.get('core_sha256'):
        raise _blocked(['core'])
    manifest = executable.parent / 'manifest.json'
    if not manifest.is_file() or manifest.stat().st_size > _MAX_MANIFEST_BYTES:
        raise _blocked(['core.manifest'])
    data = json.loads(manifest.read_text(encoding='utf-8'))
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
    chrome = executable.parent.joinpath(*relative.parts).resolve()
    if not chrome.is_relative_to(executable.parent):
        raise _blocked(['core.manifest'])
    dll_hash = sha256(chrome)
    if dll_hash != (files[names[0]] or {}).get('sha256'):
        raise _blocked(['core.chrome'])
    # Existing engine validation remains authoritative for the complete tree.
    # Binding its manifest also covers resources other than the executable/DLL.
    return {'executable': actual, 'chrome': dll_hash, 'manifest': _digest(data)}


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
      const value = await Promise.race([Promise.resolve().then(fn),
        new Promise((_, reject) => { timer=setTimeout(() => reject(new Error()), limit); })]);
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
    }));
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
    unstable = sorted(key for key in a.keys() | b.keys() if key not in a or key not in b or a[key] != b[key])
    return {'values': {key: value for key, value in a.items() if key not in unstable},
            'unstable': unstable,
            'unavailable': sorted(set(first.get('unavailable', [])) | set(second.get('unavailable', [])))}


def probe_snapshot(record, root):
    """Two reads on one owned localhost page; never copy account profile data."""
    temporary = None
    controller = None
    profile = None
    local_page = None
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
        local_page = _LoopbackPage()
        local_url = local_page.start()
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
        if str(exc).startswith('环境连续性检查'):
            raise
        raise LocalBrowserError(_FAILURE) from None
    except Exception:
        raise LocalBrowserError(_FAILURE) from None
    finally:
        cleanup_ok = True
        if local_page is not None:
            try:
                local_page.close()
            except Exception:
                cleanup_ok = False
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
                    shutil.rmtree(temporary)
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


def verify_continuity(record, root):
    """Fail closed on a missing/mismatched baseline; never learn a new machine."""
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
    actual = probe_snapshot(record, root)
    changes = [key for key, value in stable.items() if key not in actual['values'] or actual['values'][key] != value or key in actual.get('unstable', [])]
    if changes:
        raise _blocked(changes)
    if binding_for(record, root) != current:
        raise _blocked(['binding'])
    return {'passed': True, 'stable_fields': len(stable),
            'unstable_fields': list(baseline.get('unstable') or []),
            'unavailable_fields': list(baseline.get('unavailable') or [])}
