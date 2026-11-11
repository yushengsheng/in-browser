"""Synthetic telemetry and context isolation; no account or browser access."""
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from import_progress import ImportProgress, emit, observe


class ImportProgressTests(unittest.TestCase):
    def test_phase_counters_reset_and_elapsed_time_does_not_invent_progress(self):
        progress=ImportProgress()
        item={'source_key':'synthetic','info':{'name':'合成窗口'}}
        with patch('import_progress.time.monotonic', return_value=10):
            progress.begin('job',1,item)
            progress.update('copying',done=5,total=10,unit='bytes')
        with patch('import_progress.time.monotonic', return_value=20):
            value=progress.snapshot('job')
            self.assertEqual((value['done'],value['elapsed_seconds']),(5,10))
            progress.update('cookies')
            value=progress.snapshot('job')
            self.assertIsNone(value['done']);self.assertIsNone(value['unit'])
            self.assertEqual(value['timings']['copying'],10)
            self.assertIsNone(progress.snapshot('another-job'))
            summary=progress.finish()
        self.assertEqual(summary['elapsed_seconds'],10)
        self.assertNotIn('name',summary);self.assertNotIn('source_key',summary)
        self.assertIsNone(progress.snapshot('job'))

    def test_context_is_thread_local_and_released_after_exception(self):
        events=[]
        def callback(phase,**values):events.append((phase,values))
        with self.assertRaises(RuntimeError):
            with observe(callback):
                emit('copying',done=0,total=1,unit='files')
                worker=threading.Thread(target=lambda:emit('cookies'))
                worker.start();worker.join()
                raise RuntimeError('synthetic')
        emit('committing')
        self.assertEqual([phase for phase,_ in events],['copying'])

    def test_invalid_counters_and_unknown_phases_are_not_exposed(self):
        progress=ImportProgress();progress.begin('job',1,{'source_key':'synthetic'})
        with observe(progress.update):
            emit('copying',done=11,total=10,unit='bytes')
            self.assertIsNone(progress.snapshot('job')['done'])
            emit('unexpected-secret-phase')
            self.assertEqual(progress.snapshot('job')['phase'],'copying')
            emit('copying',done=0,total=0,unit='bytes')
            self.assertEqual(progress.snapshot('job')['total'],0)
            emit('inventory',done=5,unit='files')
            self.assertEqual(progress.snapshot('job')['done'],5)
            self.assertIsNone(progress.snapshot('job')['total'])


if __name__=='__main__':unittest.main(verbosity=2)
