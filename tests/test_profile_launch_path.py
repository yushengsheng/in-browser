"""Only newly owned filesystem fixtures; no browser or user-profile access."""
import ast
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import importlib.util
import json
import os
from pathlib import Path
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'app'))
from native_paths import absolute_path, io_path, resolved_path
spec = importlib.util.spec_from_file_location('profile_path_candidate', ROOT / 'app/profile_launch_path.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def shortener():
    # Reuse only the exact existing WinAPI helper, not browser module startup.
    tree = ast.parse((ROOT / 'app/browser_core.py').read_text(encoding='utf-8'))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_short_executable_path')
    namespace = {'ctypes': ctypes, 'wintypes': wintypes, 'Path': Path,
                 'absolute_path': absolute_path, 'io_path': io_path, 'resolved_path': resolved_path}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<existing-short-path-helper>', 'exec'), namespace)
    return namespace['_short_executable_path']


@contextmanager
def scope(label):
    import psutil
    base = (ROOT / 'analysis/test-runs').resolve()
    base.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix='profile-path-' + label + '-', dir=base)
    folder = Path(temporary.name).resolve()
    owner = {'pid': os.getpid(), 'token': uuid.uuid4().hex, 'synthetic': True}
    (folder / 'owner.json').write_text(json.dumps(owner), 'utf-8')
    try:
        yield folder
    finally:
        try:
            if folder.parent != base or folder.resolve() != folder or json.loads((folder / 'owner.json').read_text('utf-8')) != owner:
                raise RuntimeError('scope-proof')
            if psutil.Process().children(recursive=True):
                raise RuntimeError('scope-process')
            for path in (folder, *folder.rglob('*')):
                info = io_path(path).lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                    raise RuntimeError('scope-link')
            temporary.cleanup()
            if folder.exists():
                raise RuntimeError('scope-cleanup')
        except BaseException:
            temporary._finalizer.detach()
            raise


def expect_failure(call, code):
    try:
        call()
        return False
    except module.ProfileLaunchPathError as error:
        return error.code == code and '/' not in str(error) and '\\' not in str(error)


def metadata_tree(folder):
    result = {}
    stack = [folder]
    while stack:
        parent = stack.pop()
        info = io_path(parent).lstat()
        result[str(parent.relative_to(folder))] = module._stamp(info)
        with os.scandir(io_path(parent)) as entries:
            for entry in entries:
                path = parent / entry.name
                value = entry.stat(follow_symlinks=False)
                result[str(path.relative_to(folder))] = module._stamp(value)
                if stat.S_ISDIR(value.st_mode):
                    stack.append(path)
    return result


def main():
    checks = {}
    original_environment, original_tempdir, original_cwd = dict(os.environ), tempfile.tempdir, os.getcwd()
    with scope('probe') as probe:
        probe_path = probe
        (probe / 'nested').mkdir()
        (probe / 'nested/small').write_bytes(b'synthetic cleanup probe')
    checks['cleanup_probe_removed'] = not probe_path.exists()
    actual_alias_available = False
    actual_link_tested = False
    samples = []
    with scope('fixture') as fixture:
        fixture_path = fixture
        profile = fixture / '资料目录_中文非BMP😀_用于真实短名校验'
        io_path(profile).mkdir()
        simple = fixture / 'small'
        simple.mkdir()
        for name in ('one', 'two', 'three'):
            (simple / name).write_bytes(b'')
        choose = lambda path, **kwargs: module.choose_profile_launch_path(path, shortener=lambda _: None, windows=True, **kwargs)
        canonical_result, canonical_meta = choose(simple)
        checks['canonical_fallback_when_alias_unavailable'] = canonical_result == simple and not canonical_meta['used_short_alias']
        workflow_spec = importlib.util.spec_from_file_location('profile_path_workflow', ROOT / 'tools/verify_release_workflow.py')
        workflow = importlib.util.module_from_spec(workflow_spec)
        workflow_spec.loader.exec_module(workflow)
        candidate = workflow.verified_short_path(simple, fixture, shortener())
        checks['workflow_production_short_path_verified'] = candidate is None or (
            resolved_path(candidate) == resolved_path(simple) and io_path(candidate).samefile(io_path(simple)))
        checks['workflow_no_alias_fallback_preserved'] = workflow.verified_short_path(simple, fixture, lambda _: None) is None
        rejected = 0
        for candidate in (profile, Path('synthetic-relative'), fixture.parent):
            try:
                workflow.verified_short_path(simple, fixture, lambda _, value=candidate: value)
            except AssertionError:
                rejected += 1
        checks['workflow_invalid_aliases_rejected'] = rejected == 3
        try:
            workflow.verified_short_path(fixture.parent, fixture, lambda _: None)
        except AssertionError:
            checks['workflow_outside_input_rejected'] = True
        else:
            checks['workflow_outside_input_rejected'] = False
        checks['root_files_and_directories_counted'] = canonical_meta['entries_checked'] == 4 and canonical_meta['files_checked'] == 3 and canonical_meta['directories_checked'] == 1
        checks['wrong_directory_alias_rejected'] = expect_failure(lambda: module.choose_profile_launch_path(simple, shortener=lambda _: profile, windows=True), 'profile_path_invalid')
        checks['relative_input_rejected'] = expect_failure(lambda: choose(Path('synthetic-relative')), 'profile_path_invalid')
        checks['entry_budget_rejected'] = expect_failure(lambda: choose(simple, max_entries=2), 'profile_tree_limit')
        checks['depth_budget_rejected'] = expect_failure(lambda: choose(simple, max_depth=0), 'profile_tree_limit')
        times = iter((0, 100))
        with patch.object(module.time, 'monotonic', side_effect=lambda: next(times, 100)):
            checks['time_budget_rejected'] = expect_failure(lambda: choose(simple), 'profile_tree_limit')
        with patch.object(module.os, 'scandir', side_effect=PermissionError('synthetic-private-path')):
            checks['incomplete_metadata_scan_rejected'] = expect_failure(lambda: choose(simple), 'profile_path_invalid')
        checks['utf16_counts_non_bmp_twice'] = module.utf16_length('中文😀') == 4
        with patch('builtins.open', side_effect=AssertionError('content-read-forbidden')):
            _, no_content = choose(simple)
        checks['no_python_content_reads'] = no_content['entries_checked'] == 4
        noop = lambda _: (_ for _ in ()).throw(AssertionError('shortener-used'))
        with patch.object(module.os, 'scandir', side_effect=AssertionError('scan-used')):
            unchanged, non_windows = module.choose_profile_launch_path(simple, shortener=noop, windows=False)
        checks['non_windows_keeps_old_spelling_without_scan'] = unchanged == simple and non_windows['checked_existing_tree'] is False
        fake_reparse = SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        checks['reparse_metadata_rejected'] = expect_failure(lambda: module._kind(fake_reparse), 'profile_path_invalid')
        def sibling_write(_):
            time.sleep(.01)
            (fixture / 'normal-sibling-settings').write_bytes(b'synthetic sibling publication')
            return None
        sibling_selected, sibling_meta = module.choose_profile_launch_path(simple, shortener=sibling_write, windows=True)
        checks['ancestor_sibling_write_does_not_reject'] = sibling_selected == simple and sibling_meta['checked_existing_tree']
        replace_parent = fixture / 'replace-parent'
        replaced_parent = fixture / 'replaced-parent'
        replacement_profile = replace_parent / 'profile'
        replacement_profile.mkdir(parents=True)
        def replace_ancestor(_):
            if not replace_parent.resolve().is_relative_to(fixture.resolve()) or replaced_parent.parent.resolve() != fixture.resolve():
                raise RuntimeError('synthetic-replacement-boundary')
            replace_parent.rename(replaced_parent)
            replacement_profile.mkdir(parents=True)
            return None
        checks['ancestor_replacement_rejected'] = expect_failure(lambda: module.choose_profile_launch_path(
            replacement_profile, shortener=replace_ancestor, windows=True), 'profile_path_changed')
        link = profile / 'synthetic-link'
        junction = False
        try:
            os.symlink(simple, io_path(link), target_is_directory=True)
        except (OSError, NotImplementedError):
            if os.name == 'nt':
                environment = dict(os.environ, TEMP=str(fixture), TMP=str(fixture))
                # Directory junctions need no symlink privilege. The command
                # creates only this new owned link; it never deletes anything.
                reply = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(simple)],
                    cwd=fixture, env=environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                junction = reply.returncode == 0
        if io_path(link).is_symlink() or junction:
            try:
                actual_link_tested = True
                checks['actual_directory_link_rejected'] = expect_failure(lambda: choose(profile), 'profile_path_invalid')
                checks['actual_alias_link_rejected'] = expect_failure(lambda: module.choose_profile_launch_path(simple,
                    shortener=lambda _: link, windows=True), 'profile_path_invalid')
                (simple / 'child').mkdir()
                checks['actual_ancestor_link_rejected'] = expect_failure(lambda: choose(link / 'child'), 'profile_path_invalid')
            finally:
                if link.parent.resolve() != profile.resolve() or not profile.resolve().is_relative_to(fixture.resolve()):
                    raise RuntimeError('owned-link-boundary')
                if junction:
                    info = io_path(link).lstat()
                    if not getattr(info, 'st_file_attributes', 0) & 0x400 or resolved_path(link) != simple:
                        raise RuntimeError('owned-junction-proof')
                    io_path(link).rmdir()
                else:
                    io_path(link).unlink()
        def changed(_):
            time.sleep(.01)
            (simple / 'changed').touch()
            return None
        checks['root_metadata_change_rejected'] = expect_failure(lambda: module.choose_profile_launch_path(simple, shortener=changed, windows=True), 'profile_path_changed')
        if os.name == 'nt':
            callback = shortener()
            actual_alias = callback(profile)
            actual_alias_available = actual_alias is not None and module.utf16_length(actual_alias) < module.utf16_length(profile)
            checks['real_83_alias_available_and_shorter'] = actual_alias_available
            if actual_alias_available:
                initially_selected, initially_meta = module.choose_profile_launch_path(profile, shortener=callback, windows=True)
                checks['shorter_alias_preferred_below_260'] = initially_meta['max_canonical_utf16'] < 260 and initially_meta['used_short_alias']
                remaining = 260 - module.utf16_length(profile) - 1
                if not 1 <= remaining <= 255:
                    raise RuntimeError('fixture-length')
                name = '😀' * (remaining // 2) + ('中' if remaining % 2 else '')
                io_path(profile / name).touch()
                checks['no_alias_existing_260_path_rejected'] = expect_failure(lambda: choose(profile), 'profile_path_too_long')
                before = metadata_tree(profile)
                selected, selected_meta = module.choose_profile_launch_path(profile, shortener=callback, windows=True)
                checks['real_83_samefile_resolve_and_parent'] = (io_path(selected).samefile(io_path(profile))
                    and resolved_path(selected) == profile and io_path(selected.parent).samefile(io_path(profile.parent)))
                checks['shorter_spelling_preferred'] = selected_meta['used_short_alias'] and selected_meta['selected_root_utf16'] < selected_meta['canonical_root_utf16']
                checks['short_spelling_existing_tree_below_260'] = selected_meta['max_selected_utf16'] < 260 and selected_meta['max_canonical_utf16'] == 260
                checks['metadata_unchanged_by_short_path_selection'] = metadata_tree(profile) == before
        # Bounded small benchmark; no contents are read by the candidate.
        benchmark = fixture / 'benchmark'
        benchmark.mkdir()
        for directory in range(50):
            folder = benchmark / ('d' + str(directory))
            folder.mkdir()
            for file in range(20):
                (folder / ('file' + str(file))).touch()
        benchmark_before = metadata_tree(benchmark)
        for _ in range(3):
            _, metadata = choose(benchmark)
            samples.append({key: metadata[key] for key in ('scan_ms', 'entries_checked', 'scandir_calls', 'lstat_calls', 'entry_stat_calls')})
        checks['benchmark_full_tree_count'] = all(sample['entries_checked'] == 1051 and sample['scandir_calls'] == 51 for sample in samples)
        checks['benchmark_metadata_unchanged'] = metadata_tree(benchmark) == benchmark_before
        (benchmark / 'new-member').touch()
        _, metadata = choose(benchmark)
        checks['no_cross_call_scan_cache'] = metadata['entries_checked'] == 1052
    checks['fixture_automatically_removed'] = not fixture_path.exists()
    checks['parent_environment_unchanged'] = dict(os.environ) == original_environment
    checks['parent_tempfile_tempdir_unchanged'] = tempfile.tempdir is original_tempdir
    checks['parent_cwd_unchanged'] = os.getcwd() == original_cwd
    return {'success': all(checks.values()), 'check_count': len(checks), 'checks': checks,
        'real_83_checked': actual_alias_available, 'actual_directory_link_checked': actual_link_tested,
        'benchmark': {'samples': samples, 'median_ms': statistics.median(sample['scan_ms'] for sample in samples)},
        'browser_started': False, 'user_profile_read': False, 'app_modified': False}


if __name__ == '__main__':
    try:
        result = main()
        report = ROOT / 'analysis/reports/profile-launch-path-tests.json'
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2), 'utf-8')
        print(json.dumps(result))
        raise SystemExit(0 if result['success'] else 1)
    except Exception as error:
        print(json.dumps({'success': False, 'error_type': type(error).__name__}))
        raise SystemExit(1)
