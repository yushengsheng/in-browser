"""Bounded batch workers and reentrant window lifecycle coordination."""
from concurrent.futures import ThreadPoolExecutor, wait
from contextlib import contextmanager, nullcontext
from contextvars import copy_context
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
_FAILURE = '操作未完成，原有资料和配置已保留。请检查网络、文件占用或输入内容。'


def parallel_batch(service, action, identities):
    """Use one lazy ten-worker pool per service, including overlapping batches."""
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
    with verification_scope(), activity as ticket:
        futures = []
        try:
            def request(identity):
                admitted = operations.shared(ticket) if isinstance(operations, Operations) else nullcontext()
                with admitted:
                    return service.request(action, {'id': identity})
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
