"""Run a durable queue without eagerly submitting the remaining batch."""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait


def run_bounded(items, callback, cancelled, *, max_workers=5):
    pending = iter(items)
    exhausted = False
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='local-sync-item') as pool:
        active = set()
        while True:
            while not exhausted and len(active) < max_workers and not cancelled():
                try:
                    item = next(pending)
                except StopIteration:
                    exhausted = True
                    break
                if cancelled():
                    break
                active.add(pool.submit(callback, *item))
            if not active:
                return
            finished, active = wait(active, return_when=FIRST_COMPLETED)
            # A persistence failure interrupts dispatch; executor shutdown still
            # waits for every already executing item before releasing the lease.
            for future in finished:
                future.result()
