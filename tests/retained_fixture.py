"""Small shared helpers for owned test scopes retained for manual removal."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile


def new_scope(root, *, prefix, purpose):
    area = Path(root) / '测试文件夹'
    area.mkdir(parents=True, exist_ok=True)
    scope = Path(tempfile.mkdtemp(prefix=prefix, dir=area)).resolve()
    (scope / '.fixture-owner.json').write_text(json.dumps({
        'pid': os.getpid(), 'purpose': purpose, 'scope': str(scope),
        'retained_for_user_deletion': True}), encoding='utf-8')
    return scope


@contextmanager
def retained_scope(root, *, prefix, purpose):
    yield new_scope(root, prefix=prefix, purpose=purpose)


def test_name(test):
    case = getattr(test, 'test_case', test)
    name = getattr(case, '_testMethodName', None)
    return name if name is not None else case.id()


def report_checks(names, result):
    failed = {test_name(test) for test, _ in result.failures + result.errors}
    checks = {name: name not in failed for name in names}
    # Class-level setup/teardown errors have no method name, but must still
    # appear as failed checks instead of breaking or hiding the report.
    checks.update({name: False for name in failed if name not in checks})
    return checks, failed
