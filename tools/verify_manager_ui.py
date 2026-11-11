"""Explicit real-WebView acceptance against a marked, isolated synthetic package.

This is an acceptance tool, never a product startup hook. It creates one real
synthetic window and clones its closed empty data for bounded list fixtures.
Source discovery and source configuration are synthetic; copy, storage, bridge,
UI, import publication and cancellation use the shipped implementation.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import time
import traceback
import uuid
from unittest.mock import patch


SOURCE_ROOT = Path(__file__).resolve().parents[1]
MARKER = {'format': 1, 'purpose': 'isolated-local-creation'}
PREFIX = 'Synthetic manager UI '
HELPERS = r'''(async() => {
  window.managerQA = {
    checks: {}, stage: 'initializing',
    q: s => document.querySelector(s),
    qa: s => [...document.querySelectorAll(s)],
    pause: ms => new Promise(resolve => setTimeout(resolve, ms)),
    async wait(predicate, seconds=45) {
      const end=Date.now()+seconds*1000;
      while (Date.now()<end) {
        if (predicate()) return;
        await this.pause(75);
      }
      throw new Error('Synthetic acceptance timeout');
    },
    check(name, passed) {
      this.checks[name]=Boolean(passed);
      if (!passed) throw new Error('Synthetic acceptance assertion');
    },
    set(selector, value) {
      const control=this.q(selector);
      if (!control) throw new Error('Synthetic acceptance control');
      if (control.type==='checkbox') control.checked=Boolean(value);
      else control.value=value;
      control.dispatchEvent(new Event('input', {bubbles:true}));
      control.dispatchEvent(new Event('change', {bubbles:true}));
    },
    async confirm() {
      await this.wait(()=>this.q('#confirm-dialog').open);
      this.q('#confirm-accept').click();
      await this.wait(()=>!this.q('#confirm-dialog').open);
      await this.pause(120);
    },
    async selectSources(names) {
      this.set('#sync-select-all', false);
      for (const name of names) {
        const index=state.sync.preview.findIndex(item=>item.name===name);
        if (index<0) throw new Error('Synthetic source not found');
        this.set(`[data-sync-index="${index}"]`, true);
      }
    },
    async search(value) {
      this.set('#search-input', value);
      await this.wait(()=>state.search===value.trim());
    },
    rows() { return this.qa('#profile-rows tr[data-id]'); }
  };
  return true;
})()'''

CASES = [
    ('list_search_selection', r'''
      await Q.wait(()=>state.connected&&!state.loading&&state.profiles.length===24);
      Q.check('real_webview_bridge_ready', Q.rows().length===20);
      Q.check('pagination_initial', Q.q('#page-label').textContent==='1 / 2');
      Q.set('#select-all',true);Q.check('page_one_selects_twenty',state.selected.size===20);
      Q.q('#next-page').click();Q.check('page_two_has_four',Q.rows().length===4);
      Q.set('#select-all',true);Q.check('selection_across_pages',state.selected.size===24);
      Q.q('#clear-selection').click();Q.check('selection_cleared',state.selected.size===0);
      Q.set('#page-size','50');Q.check('page_size_changes_dom',Q.rows().length===24);
      Q.set('#page-size','20');
      await Q.search('UI 01,UI 24');
      Q.check('batch_search_or',Q.rows().length===2);
      await Q.search('note-07');Q.check('remark_search',Q.rows().length===1);
      await Q.search(Array.from({length:11},(_,i)=>'term'+i).join(','));
      Q.check('eleven_terms_rejected',Q.rows().length===0&&Q.q('#search-input').getAttribute('aria-invalid')==='true');
      Q.q('#clear-filters').click();Q.check('reset_search_immediate',state.search===''&&Q.rows().length===20);
      const input=Q.q('#search-input');input.dispatchEvent(new CompositionEvent('compositionstart',{bubbles:true}));
      input.value='UI 03';input.dispatchEvent(new InputEvent('input',{bubbles:true,isComposing:true}));
      await Q.pause(220);Q.check('composition_waits',state.search==='');
      input.dispatchEvent(new CompositionEvent('compositionend',{bubbles:true}));
      input.dispatchEvent(new InputEvent('input',{bubbles:true,isComposing:false}));
      await Q.wait(()=>state.search==='UI 03');Q.check('composition_applied',Q.rows().length===1);
      await Q.search('');Q.check('clear_search_immediate',Q.rows().length===20);
      Q.q('[data-sort="name"]').click();
      Q.check('name_sort_ascending',Q.rows()[0].querySelector('.profile-name').textContent.endsWith('01'));
      Q.q('[data-sort="name"]').click();
      Q.check('name_sort_descending',Q.rows()[0].querySelector('.profile-name').textContent.endsWith('24'));
      Q.q('[data-sort="seq"]').click();
      Q.set('#group-filter','Fixture A');Q.check('group_filter',filteredProfiles().length===12);
      Q.set('#tag-filter','even');Q.check('combined_tag_filter',filteredProfiles().length===6);
      Q.q('#clear-filters').click();
    '''),
    ('groups', r'''
      Q.q('[data-panel="groups"]').click();await Q.wait(()=>state.panel==='groups');
      Q.q('#add-group').click();Q.set('[data-group-index="2"]','Fixture New');
      Q.q('#save-groups').click();await Q.wait(()=>!state.groupsSaving&&state.groups.includes('Fixture New'));
      Q.check('group_added',state.groups.length===3);
      Q.set('[data-group-index="0"]','Fixture Renamed');Q.q('#save-groups').click();
      await Q.wait(()=>!state.groupsSaving&&state.groups.includes('Fixture Renamed'));
      Q.check('group_rename_updates_windows',state.profiles.filter(p=>p.group==='Fixture Renamed').length===12);
      Q.q('[data-remove-group="2"]').click();await Q.confirm();Q.q('#save-groups').click();
      await Q.wait(()=>!state.groupsSaving&&!state.groups.includes('Fixture New'));
      Q.check('group_removed',state.groups.length===2);
      Q.q('[data-panel="profiles"]').click();await Q.wait(()=>state.panel==='profiles');
    '''),
    ('edit_and_draft', r'''
      await Q.search('UI 01');Q.q('#profile-rows [data-action="edit"]').click();
      await Q.wait(()=>!Q.q('#profile-drawer').hidden&&state.draft);
      window.managerQA.editedId=state.draft.id;
      Q.q('[data-section="fingerprint"]').click();
      Q.check('existing_fingerprint_readonly',Q.qa('[data-field^="fingerprint."]').every(e=>e.disabled));
      Q.q('[data-section="basic"]').click();Q.set('[data-field="remark"]','edited fixture remark');
      Q.set('[data-field="tags"]','edited,fixture');Q.set('[data-field="group"]','Fixture B');
      Q.q('#save-profile').click();await Q.wait(()=>Q.q('#profile-drawer').hidden&&!state.saving);
      await Q.wait(()=>profileById(Q.editedId).remark==='edited fixture remark');
      Q.check('edit_persisted_in_ui',profileById(Q.editedId).remark==='edited fixture remark'&&profileById(Q.editedId).tags.includes('edited')&&profileById(Q.editedId).group==='Fixture B');
      Q.q('#profile-rows [data-action="edit"]').click();await Q.wait(()=>!Q.q('#profile-drawer').hidden);
      Q.set('[data-field="remark"]','discarded fixture remark');Q.q('#cancel-drawer').click();await Q.confirm();
      await Q.wait(()=>Q.q('#profile-drawer').hidden);
      Q.check('draft_discarded',profileById(Q.editedId).remark==='edited fixture remark');
      Q.q('#clear-filters').click();Q.set('#tag-filter','edited');
      Q.check('edited_tag_filter',Q.rows().length===1);Q.q('#clear-filters').click();
    '''),
    ('archive_restore_delete', r'''
      await Q.search('UI 23,UI 24');Q.set('#select-all',true);Q.q('[data-batch="archive"]').click();await Q.confirm();
      await Q.wait(()=>!state.batchBusy&&state.profiles.filter(isArchived).length===2);
      Q.check('batch_archive_keeps_records',state.profiles.length===24&&state.profiles.filter(isArchived).length===2);
      Q.q('#recycle-nav').click();await Q.wait(()=>state.panel==='recycle');
      const restores=Q.qa('[data-restore]');Q.check('recycle_has_two',restores.length===2);
      const restored=restores[0].dataset.restore;restores[0].click();
      await Q.wait(()=>!isArchived(profileById(restored))&&!state.operationIds.has(restored));
      Q.check('restore_keeps_record',state.profiles.length===24);
      Q.q('[data-delete]').click();await Q.confirm();
      await Q.wait(()=>!state.deleteBusy&&state.profiles.length===23);
      Q.check('recycle_permanent_delete',state.profiles.filter(isArchived).length===0);
      Q.q('[data-panel="profiles"]').click();await Q.wait(()=>state.panel==='profiles');Q.q('#clear-filters').click();
      await Q.search('UI 22');Q.set('#select-all',true);Q.q('[data-batch="delete"]').click();await Q.confirm();
      await Q.wait(()=>!state.deleteBusy&&state.profiles.length===22);
      Q.check('main_list_permanent_delete',Q.rows().length===0);Q.q('#clear-filters').click();
    '''),
    ('settings_export', r'''
      Q.q('[data-panel="settings"]').click();await Q.wait(()=>state.panel==='settings'&&state.settingsLoaded&&Q.q('[data-setting="start_page"]'));
      Q.set('[data-setting="start_page"]','about:blank');Q.set('[data-setting="confirm_close"]',false);
      Q.q('#save-settings').click();await Q.wait(()=>!state.settingsSaving&&!state.settingsDirty);
      const saved=await api('settings_get');Q.check('settings_public_readback',saved.start_page==='about:blank'&&saved.confirm_close===false);
      Q.q('[data-panel="profiles"]').click();await Q.wait(()=>state.panel==='profiles');
      await Q.search('UI 01');Q.set('#select-all',true);Q.q('#export-button').click();await Q.confirm();
      await Q.wait(()=>!Q.q('#export-button').disabled);Q.check('export_ui_completed',true);
      Q.q('#clear-selection').click();Q.q('#clear-filters').click();
    '''),
    ('live_status_filter', r'''
      await Q.search('UI 01');Q.q('#profile-rows [data-action="open"]').click();
      await Q.wait(()=>isRunning(profileById(Q.editedId))&&!state.operationIds.has(Q.editedId),120);
      Q.check('real_window_open_reported',Q.q('#profile-rows [data-action="activate"]')!==null);
      Q.q('[data-filter="running"]').click();Q.check('running_filter_real_window',Q.rows().length===1);
      Q.q('#profile-rows [data-action="activate"]').click();
      await Q.wait(()=>!state.operationIds.has(Q.editedId));
      Q.check('existing_window_activated',isRunning(profileById(Q.editedId)));
      Q.q('#profile-rows [data-action="menu"]').click();Q.q('[data-menu-action="close"]').click();
      await Q.wait(()=>!isRunning(profileById(Q.editedId))&&!state.operationIds.has(Q.editedId),60);
      Q.check('closed_window_removed_from_running_filter',Q.rows().length===0);
      Q.q('[data-filter="all"]').click();Q.q('#clear-filters').click();
    '''),
    ('sync_preview_and_partial_failure', r'''
      Q.q('#sync-preview-button').click();await Q.wait(()=>Q.q('#sync-dialog').open&&!state.sync.loading&&state.sync.preview.length===6);
      Q.check('sync_preview_receipt',typeof state.sync.previewId==='string'&&state.sync.previewId.length>0);
      Q.check('preview_does_not_import',state.profiles.length===22&&!state.sync.jobId);
      const refused=await window.pywebview.api.request('sync_windows',{source_keys:[state.sync.preview[0].source_key]});
      Q.check('missing_preview_receipt_rejected',refused.ok===false);
      Q.set('#sync-search','source-note-failure');Q.check('sync_remark_search',Q.qa('#sync-preview-rows input[data-sync-index]').length===1);
      Q.set('#sync-search','');await Q.selectSources(['Synthetic source OK','Synthetic source FAIL']);
      Q.check('sync_explicit_two_selected',state.sync.selected.size===2);Q.q('#sync-start').click();
      await Q.wait(()=>state.sync.jobId&&!state.sync.starting,30);
      await Q.wait(()=>state.sync.status&&state.sync.status.state!=='running',360);
      Q.check('sync_partial_failure_visible',state.sync.status.completed===1&&state.sync.status.failed===1&&Q.q('#sync-progress-summary').textContent.includes('1'));
      await Q.wait(()=>state.profiles.length===23);
      Q.check('successful_import_listed',state.profiles.some(p=>p.name==='Synthetic source OK'));
      Q.q('#sync-start').click();await Q.wait(()=>!state.sync.loading&&!state.sync.jobId);
      Q.check('duplicate_source_marked_imported',state.sync.preview.find(p=>p.name==='Synthetic source OK').status==='already_imported');
    '''),
    ('sync_cancel_start', r'''
      await Q.selectSources(['Synthetic cancel ACTIVE','Synthetic cancel PENDING']);Q.q('#sync-start').click();
      await Q.wait(()=>state.sync.jobId&&!state.sync.starting);Q.check('cancel_batch_started',state.sync.status.total===2);
    '''),
    ('sync_cancel_finish', r'''
      Q.q('#sync-cancel-job').click();await Q.wait(()=>state.sync.cancelRequested&&!state.sync.cancelling);
      await Q.wait(()=>state.sync.status&&state.sync.status.state!=='running',360);
      Q.check('cancel_stops_remaining',state.sync.status.state==='cancelled'&&state.sync.status.completed===1&&state.sync.status.failed===0);
      await Q.wait(()=>state.profiles.some(p=>p.name==='Synthetic cancel ACTIVE'));
      Q.check('current_import_survives_cancel',!state.profiles.some(p=>p.name==='Synthetic cancel PENDING'));
      Q.q('#sync-dismiss').click();await Q.wait(()=>!Q.q('#sync-dialog').open);
    '''),
    ('cancelled_batch_requires_new_preview', r'''
      const refused=await window.pywebview.api.request('resume_sync',{job_id:state.sync.jobId});
      Q.check('cancelled_job_resume_rejected',refused.ok===false);
      Q.q('#sync-preview-button').click();await Q.wait(()=>Q.q('#sync-dialog').open);
      Q.q('#sync-start').click();await Q.wait(()=>!state.sync.loading&&!state.sync.jobId);
      await Q.selectSources(['Synthetic cancel PENDING']);Q.q('#sync-start').click();
      await Q.wait(()=>state.sync.jobId&&!state.sync.starting);
      await Q.wait(()=>state.sync.status&&state.sync.status.state!=='running',360);
      Q.check('cancelled_remainder_new_batch_completed',state.sync.status.completed===1&&state.sync.status.failed===0);
      await Q.wait(()=>state.profiles.some(p=>p.name==='Synthetic cancel PENDING'));
      Q.check('cancelled_current_not_duplicated',state.profiles.filter(p=>p.name==='Synthetic cancel ACTIVE').length===1);
    '''),
    ('interruption_start', r'''
      Q.q('#sync-start').click();await Q.wait(()=>!state.sync.loading&&!state.sync.jobId);
      await Q.selectSources(['Synthetic interrupted FIRST','Synthetic interrupted SECOND']);Q.q('#sync-start').click();
      await Q.wait(()=>state.sync.jobId&&!state.sync.starting);
      Q.check('interruption_batch_started',state.sync.status.total===2);
    '''),
    ('sync_resume_after_manager_recreation', r'''
      await bootstrap({quiet:true});
      await Q.wait(()=>state.sync.status?.state==='interrupted');
      Q.check('interruption_recovered_in_real_ui',Q.q('#sync-start').textContent.includes('继续'));
      const jobId=state.sync.jobId;Q.q('#sync-start').click();
      await Q.wait(()=>!state.sync.starting&&state.sync.status?.state==='running');
      await Q.wait(()=>state.sync.status?.state!=='running',360);
      Q.check('public_resume_same_job',state.sync.jobId===jobId);
      Q.check('resumed_pending_item_completed',state.sync.status.state==='completed'&&state.sync.status.completed===2&&state.sync.status.failed===0);
      await Q.wait(()=>state.profiles.some(p=>p.name==='Synthetic interrupted SECOND'));
      Q.check('resume_does_not_duplicate_completed',state.profiles.filter(p=>p.name==='Synthetic interrupted FIRST').length===1&&state.profiles.filter(p=>p.name==='Synthetic interrupted SECOND').length===1);
      Q.q('#sync-dismiss').click();await Q.wait(()=>!Q.q('#sync-dialog').open);
    '''),
]


def require(value):
    if not value:
        raise ValueError('Synthetic acceptance boundary')


def ordinary(path, directory=False):
    path = Path(path)
    require(not path.is_symlink() and not path.is_junction())
    require(path.is_dir() if directory else path.is_file())
    return path


def safe_error(error):
    return {'error_type': type(error).__name__, 'frames': [
        {'file': Path(frame.filename).name, 'line': frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)[-5:]]}


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def finish_owned_workers(creation, synchronizers, *, timeout=60):
    """Cancel only this invocation's active jobs, then share one join budget."""
    tracked = []
    if creation.get('owner') is not None:
        tracked.append(('creation', creation['owner'], creation.get('job_id'), 'thread'))
    tracked.extend(('sync', owner, getattr(owner, 'active', None), 'worker')
        for owner in synchronizers)
    deadline = time.monotonic() + max(0, timeout)
    result = {'creation_thread_finished': True, 'sync_threads_finished': True,
        'cancel_requests': 0, 'cancel_errors': 0, 'observation_errors': 0}
    workers = []
    for kind, owner, identity, attribute in tracked:
        try:
            thread = getattr(owner, attribute, None)
            if thread is None or not thread.is_alive():
                continue
            workers.append((kind, thread))
            if identity is not None:
                try:
                    owner.cancel(identity)
                    result['cancel_requests'] += 1
                except Exception:
                    result['cancel_errors'] += 1
        except Exception:
            result['observation_errors'] += 1
            result[kind + '_thread_finished' if kind == 'creation' else 'sync_threads_finished'] = False
    for kind, thread in workers:
        try:
            thread.join(max(0, deadline - time.monotonic()))
            if thread.is_alive():
                result[kind + '_thread_finished' if kind == 'creation' else 'sync_threads_finished'] = False
        except Exception:
            result['observation_errors'] += 1
            result[kind + '_thread_finished' if kind == 'creation' else 'sync_threads_finished'] = False
    result['finished'] = result['creation_thread_finished'] and result['sync_threads_finished']
    result['success'] = result['finished'] and not result['cancel_errors'] and not result['observation_errors']
    return result


def run(args, report):
    package = ordinary(args.package.resolve(), directory=True)
    require(package != SOURCE_ROOT.resolve())
    require(json.loads(ordinary(package / 'local-creation-test.json').read_text('utf-8')) == MARKER)
    for part in package.parents:
        require(not part.is_symlink() and not part.is_junction())
    ordinary(package / 'app', directory=True)
    ordinary(package / 'runtime/webview2/msedgewebview2.exe')
    data = package / 'app/data'
    if data.exists(): ordinary(data, directory=True)
    lock = package / '.manager-ui-acceptance.lock'
    with lock.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps({'format': 1, 'synthetic': True, 'pid': os.getpid()}))
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(package / 'app'), str(package / 'tools')]
    service = window = None
    cancel_entered, cancel_release = threading.Event(), threading.Event()
    stopping = threading.Event()
    owned_ids = set()
    opened_instances = {}
    creation_task = {}
    synchronizers = []
    cleanup_result = None
    guard_stack = None
    retained_guards = []

    def cleanup_workers():
        nonlocal cleanup_result
        stopping.set()
        cancel_release.set()
        if cleanup_result is None:
            cleanup_result = finish_owned_workers(creation_task, synchronizers)
            report['worker_cleanup'] = cleanup_result
            report['checks']['creation_worker_finished'] = cleanup_result['creation_thread_finished']
            report['checks']['sync_worker_finished'] = cleanup_result['sync_threads_finished']
            report['success'] = report['success'] and cleanup_result['success']
            if not cleanup_result['success']:
                report['test_directory_retained'] = True
                report['worker_cleanup_incomplete'] = True
                if guard_stack is not None:
                    retained_guards.append(guard_stack.pop_all())
                    report['source_guards_retained'] = True
        return cleanup_result['success']

    try:
        import psutil
        import webview
        from browser_processes import profile_processes
        from creation_fingerprint import creation_defaults
        from configuration import Configuration
        from installation import initialize_installation
        from local_state import LocalBrowserError, read_encrypted
        from manager_service import ManagerService
        from window_sync import WindowSynchronizer, source_key
        from window_store import now
        existing = 0
        for process in psutil.process_iter(['exe', 'cmdline']):
            try:
                info = process.info
                exe = info.get('exe')
                if exe and Path(exe).resolve().is_relative_to(package):
                    require(process.pid == os.getpid())
                for value in info.get('cmdline') or []:
                    if str(value).startswith('--user-data-dir='):
                        require(not Path(value.split('=', 1)[1]).resolve().is_relative_to(package))
                existing += 1
            except psutil.NoSuchProcess:
                pass
        report['checks']['existing_instances_checked'] = existing > 0
        initialize_installation(data)
        service = ManagerService(data)
        require(not service.store.all())
        report['checks']['started_with_empty_catalog'] = True

        def forbidden_source(*_args, **_kwargs):
            raise LocalBrowserError('Synthetic acceptance forbids live source access.')

        with contextlib.ExitStack() as stack, contextlib.ExitStack() as worker_cleanup:
            guard_stack = stack
            # Workers must finish before the source/traffic guards are removed.
            worker_cleanup.callback(cleanup_workers)
            for name in ('vendor', 'source_settings', 'source_detail', 'prepare_source'):
                stack.enter_context(patch.object(Configuration, name, forbidden_source))
            profile = creation_defaults('148')
            profile.update(name=PREFIX + '01', urls=['about:blank'])
            profile['fingerprint'].update(fontType='2', font='Arial')
            profile['created_options'].update(workbench='disable', random_each_open=False)
            creation_task.update(owner=service.creator(), job_id=uuid.uuid4().hex)
            created = service.request('create_windows', {'request_id': creation_task['job_id'],
                'profile': profile, 'count': 1, 'random_each': False})
            require(created.get('ok') is True)
            job_id = created['data']['job_id']
            deadline = time.monotonic() + 360
            while time.monotonic() < deadline:
                reply = service.request('creation_status', {'job_id': job_id})
                require(reply.get('ok') is True)
                job = reply['data']
                if job['state'] != 'running': break
                time.sleep(.2)
            require(job['state'] == 'completed' and job['completed'] == 1)
            template = service.store.get(job['items'][0]['id'])
            template_id = template['id']
            owned_ids.add(template_id)
            require(not profile_processes(Path(template['_runtime']['profile_path']), require_inspectable=True))
            template['group'], template['tags'], template['remark'] = 'Fixture A', ['odd'], 'note-01'
            service.store.put(template, include_group=True)
            for index in range(2, 25):
                record = copy.deepcopy(template)
                identity = 'manager-ui-' + uuid.uuid4().hex
                folder = data / 'profiles' / identity
                signature = data / 'fingerprints' / (identity + '.bin')
                shutil.copytree(template['_runtime']['profile_path'], folder)
                shutil.copy2(template['_runtime']['fingerprint_path'], signature)
                record.update(id=identity, seq=index, name=PREFIX + f'{index:02}',
                    remark=f'note-{index:02}', group='Fixture A' if index <= 12 else 'Fixture B',
                    tags=['even' if index % 2 == 0 else 'odd'], created_at=now())
                record['_runtime'].update(alias=identity, name=record['name'], profile_path=str(folder),
                    fingerprint_path=str(signature))
                for key in list(record):
                    if key.startswith(('_source', '_creation')):
                        record.pop(key, None)
                service.store.put(record, include_group=True)
                service._sync(record)
                owned_ids.add(identity)
            service.request('groups_save', {'groups': ['Fixture A', 'Fixture B']})
            report['checks']['twenty_four_synthetic_profiles_seeded'] = len(service.store.all()) == 24
            report['checks']['one_real_creation_completed'] = True

            sources = package / 'analysis/manager-ui-sources'
            require(not sources.exists())
            sources.mkdir(parents=True)
            items, source_manifests, full_by_id = [], {}, {}
            names = ['Synthetic source OK', 'Synthetic source FAIL', 'Synthetic cancel ACTIVE', 'Synthetic cancel PENDING',
                'Synthetic interrupted FIRST', 'Synthetic interrupted SECOND']
            for index, name in enumerate(names):
                source_id = uuid.uuid4().hex
                folder = sources / str(index)
                shutil.copytree(template['_runtime']['profile_path'], folder)
                full = {'id': source_id, 'name': name, 'seq': index + 1,
                    'remark': 'source-note-failure' if index == 1 else 'source-note-ready',
                    'url': ['about:blank'], 'proxyType': 'noproxy',
                    'browserFingerPrint': copy.deepcopy(template['fingerprint'])}
                full['browserFingerPrint']['extendOptions'] = {'DataProtect': copy.deepcopy(template['_native']['DataProtect'])}
                full_by_id[source_id] = full
                source_manifests[source_id] = service._manifest(folder)
                items.append({'source_key': source_key(source_id), 'source_id': source_id,
                    'profile_path': str(folder), 'status': 'ready', 'info': copy.deepcopy(full), '_core_major': '148'})

            class Provider:
                interrupt_once = True

                def discover(self):
                    return copy.deepcopy(items)

                def revalidate(self, candidate):
                    selected = next(value for value in items if value['source_id'] == candidate['source_id'])
                    require(service._manifest(Path(selected['profile_path'])) == source_manifests[selected['source_id']])
                    return copy.deepcopy(selected)

                def startup(self, candidate):
                    index = next(i for i, value in enumerate(items) if value['source_id'] == candidate['source_id'])
                    if index == 1:
                        raise LocalBrowserError('Synthetic source intentionally unavailable.')
                    if index == 2:
                        cancel_entered.set()
                        require(cancel_release.wait(90))
                    if index == 5 and self.interrupt_once:
                        self.interrupt_once = False
                        raise SystemExit()
                    return {'info': copy.deepcopy(full_by_id[candidate['source_id']]),
                        'core_path': template['_runtime']['core_path']}

            def source_native(configuration, info, **_kwargs):
                require(info['id'] in full_by_id)
                native = copy.deepcopy(template['_native'])
                return native, configuration.sign(native, core_major='148')

            stack.enter_context(patch.object(Configuration, 'build_source', source_native))
            provider = Provider()
            sync = WindowSynchronizer(service, provider=provider)
            synchronizers.append(sync)
            service._synchronizer = sync
            action_counts = {}
            export_path = package / 'analysis/manager-ui-export.localprofiles'
            require(not export_path.exists())

            class Bridge:
                def request(self, action, payload=None):
                    if stopping.is_set():
                        return {'ok': False, 'error': 'Synthetic acceptance is stopping.'}
                    action_counts[action] = action_counts.get(action, 0) + 1
                    result = service.request(action, payload)
                    if action in ('open', 'activate') and result.get('ok') is True:
                        identity = (payload or {}).get('id')
                        report['checks']['live_process_identity_verified'] = service.controller._record_valid(identity)
                        if action == 'open':
                            opened_instances[identity] = copy.deepcopy(service.controller.state[identity])
                    if action == 'cancel_sync' and result.get('ok') is True:
                        cancel_release.set()
                    return result

            webview.settings['WEBVIEW2_RUNTIME_PATH'] = str(package / 'runtime/webview2')
            window = webview.create_window('Synthetic manager acceptance', str(package / 'app/ui/index.html'),
                js_api=Bridge(), width=1460, height=920, min_size=(900, 600))
            service.window = window
            original_dialog = window.create_file_dialog

            def save_dialog(dialog_type, *values, **options):
                require(dialog_type == webview.FileDialog.SAVE)
                report['checks']['export_dialog_destination_isolated'] = True
                return (str(export_path),)

            window.create_file_dialog = save_dialog

            def evaluate(expression, timeout=420):
                finished = threading.Event()
                value = {}

                def accept(result):
                    if isinstance(result, dict): value.update(result)
                    else: value['value'] = result
                    finished.set()

                window.evaluate_js(expression, callback=accept)
                require(finished.wait(timeout))
                return value

            def test():
                nonlocal service, sync
                try:
                    evaluate(HELPERS)
                    for stage, body in CASES:
                        require(not stopping.is_set())
                        report['stage'] = stage
                        write_report(args.report, report)
                        if stage == 'sync_cancel_finish': require(cancel_entered.wait(90))
                        if stage == 'sync_resume_after_manager_recreation':
                            sync.worker.join(360)
                            require(not sync.worker.is_alive())
                            previous = sync.latest()
                            require(previous['state'] == 'running' and previous['completed'] == 1)
                            service = ManagerService(data)
                            service.window = window
                            sync = WindowSynchronizer(service, provider=provider)
                            synchronizers.append(sync)
                            service._synchronizer = sync
                            report['checks']['fresh_manager_marks_worker_interrupted'] = sync.latest()['state'] == 'interrupted'
                            report['bounded_worker_interruption'] = True
                        expression = '(async()=>{const Q=window.managerQA;Q.stage=' + json.dumps(stage) + ';try{' + body + \
                            ';return {ok:true,checks:Q.checks};}catch(error){return {ok:false,checks:Q.checks,error_type:error.name};}})()'
                        result = evaluate(expression)
                        checks = result.get('checks') or {}
                        require(isinstance(checks, dict) and all(isinstance(v, bool) for v in checks.values()))
                        report['checks'].update(checks)
                        if result.get('ok') is not True:
                            report['ui_error_type'] = result.get('error_type', 'Unknown')
                            raise AssertionError('Synthetic UI case failed')
                        report['completed_stages'].append(stage)
                        print(json.dumps({'stage': stage, 'passed': True}), file=sys.__stdout__, flush=True)
                    exported = read_encrypted(export_path, root=data)
                    report['checks']['encrypted_export_exact_selection'] = (
                        exported.get('format') == 'local-profiles-1' and len(exported.get('profiles', [])) == 1
                        and exported['profiles'][0]['id'] == template_id)
                    current = service.store.get(template_id)
                    report['checks']['edited_record_readback'] = (current['remark'] == 'edited fixture remark'
                        and current['tags'] == ['edited', 'fixture'] and current['group'] == 'Fixture B')
                    report['checks']['fingerprint_and_native_preserved'] = (
                        current['fingerprint'] == template['fingerprint'] and current['_native'] == template['_native'])
                    report['checks']['source_trees_unchanged'] = all(
                        service._manifest(Path(item['profile_path'])) == source_manifests[item['source_id']] for item in items)
                    reopened = ManagerService(data)
                    report['checks']['fresh_manager_reads_settings'] = reopened.settings()['start_page'] == 'about:blank' and reopened.settings()['confirm_close'] is False
                    report['checks']['fresh_manager_reads_resumed_job'] = reopened.synchronizer().latest()['state'] == 'completed'
                    report['bridge_action_counts'] = action_counts
                    report['success'] = all(report['checks'].values())
                    report['stage'] = 'completed'
                except Exception as error:
                    report.update(safe_error(error))
                    report['success'] = False
                finally:
                    cleanup_workers()
                    window.create_file_dialog = original_dialog
                    write_report(args.report, report)
                    window.destroy()

            started = threading.Event()

            def loaded():
                if not started.is_set():
                    started.set()
                    threading.Thread(target=test, name='synthetic-manager-qa', daemon=True).start()

            window.events.loaded += loaded
            webview.start(gui='edgechromium', private_mode=True,
                storage_path=str(package / 'analysis/manager-ui-webview'))
    finally:
        workers_finished = cleanup_workers()
        safe_to_release = workers_finished
        if service is not None and workers_finished:
            for identity, original in opened_instances.items():
                current = service.controller.state.get(identity) or {}
                if current.get('pid') == original.get('pid') and service.controller._record_valid(identity):
                    service.close(identity)
            running = 0
            for record in service.store.all():
                profile_path = Path(record['_runtime']['profile_path']).resolve()
                require(profile_path.is_relative_to(data.resolve()))
                running += len(profile_processes(profile_path, require_inspectable=True))
            report['checks']['no_test_browser_remaining'] = running == 0
            report['test_records_retained'] = len(service.store.all())
            report['success'] = report['success'] and running == 0
            safe_to_release = running == 0
        if safe_to_release:
            lock.unlink(missing_ok=True)
        else:
            report['success'] = False
            report['ownership_marker_retained'] = True
            report['test_directory_retained'] = True
            report['checks']['no_test_browser_remaining'] = False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--package', type=Path)
    parser.add_argument('--report', type=Path, default=SOURCE_ROOT / 'analysis/sync-repair-20261111-ui/manager-ui.json')
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({'executed': False, 'requires_execute': True}))
        return 0
    report = {'success': False, 'synthetic': True, 'real_webview': True,
        'source_api_synthetic': True, 'public_seed_network_possible': True,
        'checks': {}, 'completed_stages': [], 'stage': 'preparing',
        'not_covered': ['real_account_login', 'physical_second_machine', 'browser_batch_open_close',
            'proxy_protocols', 'native_window_arrangement', 'crash_interruption_resume', 'all_21_cores'],
        'fixture_limits': ['one_real_148_creation_then_closed_profile_clones', 'export_native_picker_redirected_to_isolated_path']}
    started = time.monotonic()
    try:
        require(os.name == 'nt' and args.package is not None)
        args.report = args.report.absolute()
        with open(os.devnull, 'w', encoding='utf-8') as quiet:
            with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
                run(args, report)
    except Exception as error:
        report.update(safe_error(error))
        report['success'] = False
    report['elapsed_seconds'] = round(time.monotonic() - started, 1)
    write_report(args.report, report)
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
