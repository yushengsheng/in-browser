"""Bounded batch workers and reentrant window lifecycle coordination."""
from concurrent.futures import ThreadPoolExecutor, wait
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar, copy_context
import re
import threading
import time

from local_state import LocalBrowserError
from engine_validation import verification_scope


class WindowLocks:
    def __init__(self):
        self._guard = threading.Lock()
        self._windows = {}

    @contextmanager
    def hold(self, identity, *, blocking=True):
        with self._guard:
            entry = self._windows.setdefault(str(identity), [threading.RLock(), 0])
            entry[1] += 1
        acquired = False
        try:
            acquired = entry[0].acquire(blocking=blocking)
            yield acquired
        finally:
            if acquired:
                entry[0].release()
            with self._guard:
                entry[1] -= 1
                if not entry[1]:
                    self._windows.pop(str(identity), None)


class Operations:
    """Exclusive catalog actions, shared activity, and one lock per window.

    The old acquire(False) exit check remains exclusive: any active batch,
    import, or window operation keeps the manager open until it has finished.
    """
    def __init__(self):
        self._condition = threading.Condition(threading.RLock())
        self._owner = None
        self._depth = 0
        self._readers = {}
        self._tickets = {}
        self._waiting = 0
        self._windows = WindowLocks()

    def acquire(self, blocking=True, timeout=-1):
        owner = threading.get_ident()
        deadline = None if timeout < 0 else time.monotonic() + timeout
        with self._condition:
            if self._owner == owner:
                self._depth += 1
                return True
            self._waiting += 1
            try:
                while self._owner is not None or sum(self._readers.values()) != self._readers.get(owner, 0):
                    if not blocking:
                        return False
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        return False
                    self._condition.wait(remaining)
                self._owner = owner
                self._depth = 1
                return True
            finally:
                self._waiting -= 1
                self._condition.notify_all()

    def release(self):
        with self._condition:
            if self._owner != threading.get_ident():
                raise RuntimeError('Cannot release an unowned operation')
            self._depth -= 1
            if not self._depth:
                self._owner = None
                self._condition.notify_all()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_):
        self.release()

    @contextmanager
    def shared(self, ticket=None):
        owner = threading.get_ident()
        with self._condition:
            while (self._owner not in (None, owner)
                   or self._waiting and owner not in self._readers and self._owner != owner and ticket not in self._tickets):
                self._condition.wait()
            ticket = ticket if ticket in self._tickets else object()
            self._tickets[ticket] = self._tickets.get(ticket, 0) + 1
            self._readers[owner] = self._readers.get(owner, 0) + 1
        try:
            yield ticket
        finally:
            with self._condition:
                count = self._readers[owner] - 1
                if count:
                    self._readers[owner] = count
                else:
                    self._readers.pop(owner)
                count = self._tickets[ticket] - 1
                if count:
                    self._tickets[ticket] = count
                else:
                    self._tickets.pop(ticket)
                self._condition.notify_all()

    @contextmanager
    def window(self, identity):
        with self.shared(), self._windows.hold(identity):
            yield


_EXECUTOR_LOCK = threading.Lock()
_PROGRESS_LOCK = threading.Lock()
_PROGRESS_LIMIT = 32
_PROGRESS_TTL = 60
_PROGRESS_CONTEXT = ContextVar('batch_progress', default=None)
_STAGES = frozenset(('waiting', 'checking', 'signature', 'environment', 'profile',
                     'engine', 'proxy', 'launching', 'page', 'closing', 'saving', 'proxy_stop'))
_TERMINAL_STAGES = frozenset(('succeeded', 'failed', 'unconfirmed'))
_FAILURE = '操作未完成，原有资料和配置已保留。请检查网络、文件占用或输入内容。'


def _progress_token(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,96}', value):
        raise LocalBrowserError('批量进度标识无效，请重新操作。')
    return value


class _BatchProgress:
    """Small, memory-only snapshots; no profile data or exception text."""
    def __init__(self):
        self.lock = threading.Lock()
        self.records = {}

    def _prune(self):
        now = time.monotonic()
        for token, record in list(self.records.items()):
            if record['ended'] is not None and now - record['ended'] >= _PROGRESS_TTL:
                del self.records[token]

    def begin(self, token, action, identities):
        with self.lock:
            self._prune()
            if token in self.records:
                raise LocalBrowserError('批量进度标识已使用，请重新操作。')
            if len(self.records) >= _PROGRESS_LIMIT:
                finished = next((key for key, value in self.records.items() if value['ended'] is not None), None)
                if finished is None:
                    # Progress capacity must not change the shared worker limit
                    # or prevent an otherwise valid operation.
                    return None
                del self.records[finished]
            record = {'token': token, 'action': action, 'ended': None,
                      'items': dict.fromkeys(identities[:100], 'queued')}
            self.records[token] = record
            return record

    def stage(self, record, identity, stage):
        with self.lock:
            if (self.records.get(record['token']) is record and record['ended'] is None
                    and identity in record['items'] and record['items'][identity] not in _TERMINAL_STAGES):
                record['items'][identity] = stage

    def finish(self, record):
        with self.lock:
            record['ended'] = time.monotonic()
            for identity, stage in record['items'].items():
                if stage not in _TERMINAL_STAGES:
                    record['items'][identity] = 'unconfirmed'

    def snapshot(self, token):
        with self.lock:
            self._prune()
            record = self.records.get(token)
            if record is None:
                return {'found': False, 'operation_token': token}
            items = [{'id': identity, 'stage': stage} for identity, stage in record['items'].items()]
            completed = sum(item['stage'] == 'succeeded' for item in items)
            failed = sum(item['stage'] == 'failed' for item in items)
            return {'found': True, 'operation_token': token, 'action': record['action'],
                    'total': len(items), 'processed': completed + failed, 'completed': completed,
                    'failed': failed, 'finished': record['ended'] is not None, 'items': items}


def batch_progress(service, operation_token):
    token = _progress_token(operation_token)
    registry = vars(service).get('_batch_progress')
    return registry.snapshot(token) if registry is not None else {'found': False, 'operation_token': token}


def report_stage(stage):
    """Report a fixed stage for the current batch worker, if there is one."""
    context = _PROGRESS_CONTEXT.get()
    if context is not None and stage in _STAGES:
        registry, record, identity = context
        registry.stage(record, identity, stage)


@contextmanager
def _track_progress(service, action, identities, operation_token):
    registry = record = None
    if operation_token is not None:
        token = _progress_token(operation_token)
        with _PROGRESS_LOCK:
            registry = vars(service).get('_batch_progress')
            if registry is None:
                registry = service._batch_progress = _BatchProgress()
        record = registry.begin(token, action, identities)
    try:
        yield (registry, record) if record is not None else None
    finally:
        if record is not None:
            registry.finish(record)


def parallel_batch(service, action, identities, operation_token=None):
    with _track_progress(service, action, identities, operation_token) as progress:
        return _parallel_batch(service, action, identities, progress)


def _parallel_batch(service, action, identities, progress):
    """Use one lazy ten-worker pool per service, including overlapping batches."""
    from browser_processes import process_scan_scope
    with _EXECUTOR_LOCK:
        if vars(service).get('_batch_closed'):
            raise LocalBrowserError('管理器正在退出，请重新打开后再操作。')
        executor = vars(service).get('_batch_executor')
        if executor is None:
            executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='window-batch')
            service._batch_executor = executor
    operations = getattr(service, 'operations', None)
    activity = operations.shared() if isinstance(operations, Operations) else nullcontext()
    # Pinned read handles let this batch share engine digests without keeping
    # trust across operations. Every window still checks the complete tree.
    with verification_scope(), process_scan_scope(), activity as ticket:
        futures = []
        try:
            def request(identity):
                context = (*progress, identity) if progress is not None else None
                context_token = _PROGRESS_CONTEXT.set(context)
                admitted = operations.shared(ticket) if isinstance(operations, Operations) else nullcontext()
                stage = 'unconfirmed'
                try:
                    report_stage('waiting')
                    with admitted:
                        reply = service.request(action, {'id': identity})
                    stage = 'succeeded' if reply['ok'] else 'failed'
                    return reply
                except Exception:
                    stage = 'failed'
                    raise
                finally:
                    if progress is not None:
                        progress[0].stage(progress[1], identity, stage)
                    _PROGRESS_CONTEXT.reset(context_token)
            for identity in identities:
                futures.append(executor.submit(copy_context().run, request, identity))
            completed = 0
            errors = []
            # Consume in selection order so partial failures keep the API's
            # existing deterministic response, regardless of completion order.
            for identity, future in zip(identities, futures):
                try:
                    reply = future.result()
                    if reply['ok']:
                        completed += 1
                    else:
                        errors.append({'id': identity, 'error': reply['error']})
                except Exception:
                    errors.append({'id': identity, 'error': _FAILURE})
            return {'completed': completed, 'errors': errors}
        finally:
            # Cancellation never interrupts a running browser save or launch.
            # Drain those workers before releasing the manager's activity gate.
            for future in futures:
                future.cancel()
            wait(futures)


def shutdown_batches(service):
    with _EXECUTOR_LOCK:
        service._batch_closed = True
        executor = vars(service).get('_batch_executor')
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
    registry = vars(service).get('_batch_progress')
    if registry is not None:
        with registry.lock:
            registry.records.clear()
