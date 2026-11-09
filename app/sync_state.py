"""Durable, bounded import queue and a crash-released single-worker lease."""
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3

from local_state import LocalBrowserError


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _plain(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _tuples(value):
    return tuple(_tuples(item) for item in value) if isinstance(value, list) else value


class WorkerLease:
    """The OS releases this advisory lock even when the process is terminated."""
    def __init__(self, root):
        self.path = Path(root) / '.sync-worker.lock'
        self.handle = None

    def acquire(self):
        if self.handle is not None:
            return True
        handle = self.path.open('a+b')
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b'0')
                handle.flush()
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
        self.handle = handle
        return True

    def release(self):
        handle, self.handle = self.handle, None
        if handle is None:
            return
        try:
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            handle.close()


class SyncState:
    def __init__(self, store):
        self.store = store
        with store.lock, store.connect() as con:
            con.execute('CREATE TABLE IF NOT EXISTS sync_jobs ('
                        'job_id TEXT PRIMARY KEY,created_at TEXT NOT NULL,state TEXT NOT NULL,'
                        'phase TEXT NOT NULL,current INTEGER NOT NULL,total INTEGER NOT NULL,'
                        'completed INTEGER NOT NULL DEFAULT 0,skipped INTEGER NOT NULL DEFAULT 0,'
                        'failed INTEGER NOT NULL DEFAULT 0,cancel_requested INTEGER NOT NULL DEFAULT 0,'
                        'message TEXT,warnings_total INTEGER NOT NULL DEFAULT 0)')
            con.execute('CREATE TABLE IF NOT EXISTS sync_items ('
                        'job_id TEXT NOT NULL,ordinal INTEGER NOT NULL,source_key TEXT NOT NULL,'
                        'name BLOB NOT NULL,candidate BLOB NOT NULL,state TEXT NOT NULL DEFAULT \'pending\','
                        'message TEXT,PRIMARY KEY(job_id,ordinal),UNIQUE(job_id,source_key))')
            con.execute('CREATE INDEX IF NOT EXISTS sync_items_pending ON sync_items(job_id,state,ordinal)')
            con.execute("CREATE INDEX IF NOT EXISTS sync_items_results ON sync_items(job_id,ordinal) WHERE state IN ('completed','skipped','failed')")
            con.execute('CREATE TABLE IF NOT EXISTS import_intents ('
                        'intent_id TEXT PRIMARY KEY,source_key TEXT NOT NULL,profile_id TEXT NOT NULL UNIQUE,'
                        'work_id TEXT NOT NULL,state TEXT NOT NULL,data BLOB,job_id TEXT,ordinal INTEGER)')
            con.execute('CREATE INDEX IF NOT EXISTS import_intents_source ON import_intents(source_key)')

    def interrupt_running(self):
        with self.store.lock, self.store.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            con.execute("UPDATE sync_items SET state='pending' WHERE state='running' AND job_id IN "
                        "(SELECT job_id FROM sync_jobs WHERE state='running')")
            con.execute("UPDATE sync_jobs SET state='interrupted',phase='finished',message=? WHERE state='running'",
                        ('上次同步已中断，已导入副本保留；可继续剩余项。',))

    def create(self, identity, candidates):
        def rows():
            for ordinal, candidate in enumerate(candidates, 1):
                name = str((candidate.get('info') or {}).get('name') or '本机资料窗口')
                yield identity, ordinal, candidate['source_key'], self.store.pack(name), self.store.pack(_plain(candidate))
        with self.store.lock, self.store.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            con.execute('INSERT INTO sync_jobs(job_id,created_at,state,phase,current,total) VALUES (?,?,?,?,?,?)',
                        (identity, _now(), 'running', 'preparing', 0, 0))
            con.executemany('INSERT INTO sync_items(job_id,ordinal,source_key,name,candidate) VALUES (?,?,?,?,?)', rows())
            con.execute('UPDATE sync_jobs SET total=(SELECT COUNT(*) FROM sync_items WHERE job_id=?) WHERE job_id=?', (identity, identity))

    def latest(self):
        with self.store.lock, self.store.connect() as con:
            row = con.execute('SELECT job_id FROM sync_jobs ORDER BY rowid DESC LIMIT 1').fetchone()
        return self.status(row[0]) if row else None

    def status(self, identity, *, after=None, limit=100, missing_ok=False):
        limit = min(100, max(1, int(limit)))
        with self.store.lock, self.store.connect() as con:
            con.row_factory = sqlite3.Row
            row = con.execute('SELECT * FROM sync_jobs WHERE job_id=?', (identity,)).fetchone()
            if row is None:
                if missing_ok:return None
                raise LocalBrowserError('同步任务记录不存在。')
            result = dict(row)
            terminal = "state IN ('completed','skipped','failed')"
            if after is None:
                rows = con.execute('SELECT ordinal,source_key,name,state,message FROM sync_items WHERE job_id=? AND '
                                   + terminal + ' ORDER BY ordinal DESC LIMIT ?', (identity, limit)).fetchall()[::-1]
            else:
                rows = con.execute('SELECT ordinal,source_key,name,state,message FROM sync_items WHERE job_id=? AND '
                                   + terminal + ' AND ordinal>? ORDER BY ordinal LIMIT ?',
                                   (identity, max(0, int(after)), limit)).fetchall()
        result['cancel_requested'] = bool(result['cancel_requested'])
        result['items_total'] = result['completed'] + result['skipped'] + result['failed']
        result['items'] = [{'index': item['ordinal'], 'source_key': item['source_key'], 'name': self.store.unpack(item['name']),
                            'status': item['state'], 'message': item['message']} for item in rows]
        result['next_cursor'] = rows[-1]['ordinal'] if rows else max(0, int(after or 0))
        return result

    def update(self, identity, **values):
        allowed = {'state', 'phase', 'current', 'message'}
        if not values or set(values) - allowed:
            raise ValueError('Invalid sync update')
        with self.store.lock, self.store.connect() as con:
            con.execute('UPDATE sync_jobs SET ' + ','.join(key + '=?' for key in values) + ' WHERE job_id=?',
                        (*values.values(), identity))

    def cancelled(self, identity):
        with self.store.lock, self.store.connect() as con:
            row = con.execute('SELECT cancel_requested FROM sync_jobs WHERE job_id=?', (identity,)).fetchone()
        return not row or bool(row[0])

    def cancel(self, identity):
        with self.store.lock, self.store.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            row = con.execute('SELECT state FROM sync_jobs WHERE job_id=?', (identity,)).fetchone()
            if row is None:
                raise LocalBrowserError('同步任务不存在。')
            con.execute('UPDATE sync_jobs SET cancel_requested=1 WHERE job_id=?', (identity,))
            if row[0] == 'interrupted':
                con.execute("UPDATE sync_jobs SET state='cancelled',phase='finished' WHERE job_id=?", (identity,))

    def resume(self, identity):
        with self.store.lock, self.store.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            row = con.execute('SELECT state FROM sync_jobs WHERE job_id=?', (identity,)).fetchone()
            if row is None or row[0] != 'interrupted':
                raise LocalBrowserError('该同步任务不能继续，请重新读取来源。')
            con.execute("UPDATE sync_items SET state='pending' WHERE job_id=? AND state='running'", (identity,))
            con.execute("UPDATE sync_jobs SET state='running',phase='preparing',cancel_requested=0,message=NULL WHERE job_id=?", (identity,))

    def pending(self, identity):
        cursor = 0
        while True:
            with self.store.lock, self.store.connect() as con:
                rows = con.execute("SELECT ordinal,candidate FROM sync_items WHERE job_id=? AND state='pending' AND ordinal>? ORDER BY ordinal LIMIT 100",
                                   (identity, cursor)).fetchall()
            if not rows:
                return
            for ordinal, blob in rows:
                candidate = self.store.unpack(blob)
                if '_snapshot' in candidate:
                    candidate['_snapshot'] = _tuples(candidate['_snapshot'])
                yield ordinal, candidate
                cursor = ordinal

    def begin_item(self, identity, ordinal):
        with self.store.lock, self.store.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            con.execute("UPDATE sync_items SET state='running' WHERE job_id=? AND ordinal=? AND state='pending'", (identity, ordinal))
            # Permanent deletion can remove historical items without renumbering
            # authenticated intents or result cursors for the remaining items.
            con.execute("UPDATE sync_jobs SET current=(SELECT count(*) FROM sync_items WHERE job_id=? AND ordinal<=?),phase='checking' WHERE job_id=?", (identity, ordinal, identity))

    @staticmethod
    def complete_item(con, identity, ordinal, status, message):
        if status not in ('completed', 'skipped', 'failed'):
            raise ValueError('Invalid item state')
        row = con.execute('SELECT state FROM sync_items WHERE job_id=? AND ordinal=?', (identity, ordinal)).fetchone()
        previous = row[0] if row else None
        if previous in ('pending', 'running') or (previous == 'failed' and status == 'completed'):
            con.execute('UPDATE sync_items SET state=?,message=? WHERE job_id=? AND ordinal=?', (status, message, identity, ordinal))
            if previous == 'failed':
                con.execute('UPDATE sync_jobs SET failed=failed-1 WHERE job_id=?', (identity,))
            con.execute('UPDATE sync_jobs SET ' + status + '=' + status + '+1 WHERE job_id=?', (identity,))

    def finish_item(self, identity, ordinal, status, message):
        with self.store.lock, self.store.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            self.complete_item(con, identity, ordinal, status, message)

    def warning(self, identity):
        if identity is None:
            return
        with self.store.lock, self.store.connect() as con:
            con.execute('UPDATE sync_jobs SET warnings_total=warnings_total+1 WHERE job_id=?', (identity,))

    def intent(self, intent_id, key, profile_id, work_id, job_item=None):
        identity={'intent_id':intent_id,'source_key':key,'profile_id':profile_id,'work_id':work_id,
                  'job_id':job_item[0] if job_item else None,'ordinal':job_item[1] if job_item else None}
        data=self.store.pack({'format':1,'ownership':identity,'phase':'copying'})
        with self.store.lock, self.store.connect() as con:
            con.execute('INSERT INTO import_intents(intent_id,source_key,profile_id,work_id,state,data,job_id,ordinal) VALUES (?,?,?,?,?,?,?,?)',
                        (intent_id, key, profile_id, work_id, 'copying', data, *(job_item or (None, None))))
        return self.get_intent(intent_id)

    @staticmethod
    def validate_intent(item):
        data=item.get('data')
        fields=('intent_id','source_key','profile_id','work_id','job_id','ordinal')
        expected={field:item.get(field) for field in fields}
        if (not isinstance(data,dict) or data.get('format')!=1 or data.get('ownership')!=expected or
                data.get('phase')!=('prepared' if item.get('state') in ('prepared','committed') else item.get('state'))):
            raise LocalBrowserError('同步恢复记录无法认证，已保留全部资料。')
        return expected

    def _decode_intent(self,item):
        item=dict(item)
        try:
            if item.get('data') is None:raise ValueError('Unauthenticated intent')
            item['data']=self.store.unpack(item['data'])
            self.validate_intent(item)
            if item['data']['phase']=='prepared':
                item['data']['record']=self.store.unpack(bytes.fromhex(item['data']['record']))
        except Exception:
            item['data']=None
            item['_authentication_failed']=True
        return item

    def get_intent(self,identity):
        with self.store.lock,self.store.connect() as con:
            con.row_factory=sqlite3.Row
            row=con.execute('SELECT * FROM import_intents WHERE intent_id=?',(identity,)).fetchone()
        if row is None:raise LocalBrowserError('同步恢复记录不存在。')
        item=self._decode_intent(row);self.validate_intent(item)
        return item

    def prepare(self, intent_id, record, manifest, signature_hash):
        # Pack the record itself so managed runtime paths retain portable encoding.
        with self.store.lock, self.store.connect() as con:
            con.execute('BEGIN IMMEDIATE');con.row_factory=sqlite3.Row
            row=con.execute('SELECT * FROM import_intents WHERE intent_id=?',(intent_id,)).fetchone()
            if row is None:raise LocalBrowserError('同步准备记录已失效，未发布副本。')
            item=self._decode_intent(row);ownership=self.validate_intent(item)
            data=self.store.pack({'format':1,'ownership':ownership,'phase':'prepared',
                                 'record':self.store.pack(record).hex(),'manifest':manifest,'signature_hash':signature_hash})
            changed=con.execute("UPDATE import_intents SET state='prepared',data=? WHERE intent_id=? AND state='copying'", (data, intent_id)).rowcount
            if changed!=1:raise LocalBrowserError('同步准备记录已失效，未发布副本。')
        return self.get_intent(intent_id)

    def intents(self, key=None):
        cursor=0
        while True:
            with self.store.lock, self.store.connect() as con:
                con.row_factory = sqlite3.Row
                rows = con.execute('SELECT rowid AS cursor,* FROM import_intents WHERE rowid>?'
                                   + (' AND source_key=?' if key else '') + ' ORDER BY rowid LIMIT 32',
                                   (cursor,key) if key else (cursor,)).fetchall()
            if not rows:return
            for row in rows:
                item = dict(row);cursor=item.pop('cursor')
                yield self._decode_intent(item)

    def discard_intent(self, identity):
        with self.store.lock, self.store.connect() as con:
            con.execute('BEGIN IMMEDIATE');con.row_factory=sqlite3.Row
            row=con.execute('SELECT * FROM import_intents WHERE intent_id=?',(identity,)).fetchone()
            if row is None:return
            self.validate_intent(self._decode_intent(row))
            con.execute('DELETE FROM import_intents WHERE intent_id=?', (identity,))
