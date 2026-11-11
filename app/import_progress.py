"""In-memory import telemetry; never used as proof of a durable import."""
from contextlib import contextmanager
from contextvars import ContextVar
import threading
import time


PHASES = frozenset(('checking', 'preparing', 'engine', 'inventory', 'source_hash',
    'copying', 'source_verify', 'copy_verify', 'validating', 'portable_keys', 'cookies',
    'baseline_first', 'baseline_second', 'baseline_verify', 'flushing', 'final_hash', 'committing'))
_observer = ContextVar('import_progress', default=None)


@contextmanager
def observe(callback):
    token = _observer.set(callback)
    try:
        yield
    finally:
        _observer.reset(token)


def emit(phase, *, done=None, total=None, unit=None):
    callback = _observer.get()
    if callback is not None and phase in PHASES:
        callback(phase, done=done, total=total, unit=unit)


class ImportProgress:
    def __init__(self):
        self.lock = threading.Lock()
        self.current = None

    def begin(self, job, index, candidate):
        with self.lock:
            now = time.monotonic()
            self.started = self.phase_started = now
            self.job = job
            self.timings = {}
            info = candidate.get('info') or {}
            self.current = {'index': index, 'source_key': candidate['source_key'],
                'name': str(info.get('name') or '本机资料窗口')[:1024], 'phase': 'checking',
                'done': None, 'total': None, 'unit': None}

    def update(self, phase, *, done=None, total=None, unit=None):
        if phase not in PHASES:
            return
        with self.lock:
            if self.current is None:
                return
            now = time.monotonic()
            if phase != self.current['phase']:
                previous = self.current['phase']
                self.timings[previous] = self.timings.get(previous, 0) + max(0, now - self.phase_started)
                self.phase_started = now
            known = (type(done) is int and done >= 0
                     and (total is None or (type(total) is int and done <= total))
                     and unit in ('bytes', 'files', 'steps'))
            self.current.update(phase=phase, done=done if known else None,
                                total=total if known else None, unit=unit if known else None)

    def snapshot(self, job):
        with self.lock:
            if self.current is None or job != self.job:
                return None
            now = time.monotonic()
            return dict(self.current, elapsed_seconds=round(max(0, now - self.started), 2),
                phase_elapsed_seconds=round(max(0, now - self.phase_started), 2),
                timings={key: round(value, 2) for key, value in self.timings.items()})

    def finish(self):
        with self.lock:
            if self.current is None:
                return None
            now = time.monotonic(); phase = self.current['phase']
            self.timings[phase] = self.timings.get(phase, 0) + max(0, now - self.phase_started)
            result = {'kind': 'timing', 'ordinal': self.current['index'],
                'elapsed_seconds': round(max(0, now - self.started), 2),
                'phases': {key: round(value, 2) for key, value in self.timings.items()}}
            self.current = None
            return result
