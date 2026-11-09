"""Synthetic continuity checks; no account data, browser process, or network."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

import fingerprint_continuity as continuity
from environment_compatibility import compatibility_candidate, validated_environment_args
from local_state import LocalBrowserError


MOTION = '--force-prefers-reduced-motion'
NO_MOTION = '--force-prefers-no-reduced-motion'
GPU = ['--use-angle=d3d11', '--ignore-gpu-blocklist']


class EnvironmentArgumentTests(unittest.TestCase):
    def test_only_exact_ordered_choices_are_allowed(self):
        allowed = [[], [MOTION], [NO_MOTION], GPU, [MOTION, *GPU], [NO_MOTION, *GPU]]
        self.assertEqual(validated_environment_args({}), [])
        for arguments in allowed:
            with self.subTest(arguments=arguments):
                actual = validated_environment_args({'environment_args': arguments})
                self.assertEqual(actual, arguments)
                self.assertIsNot(actual, arguments)

    def test_arbitrary_conflicting_and_malformed_arguments_are_rejected(self):
        invalid = [None, '', {}, (), [None], [['nested']], [MOTION, NO_MOTION],
                   [MOTION, MOTION], list(reversed(GPU)), [GPU[0]], [GPU[1]],
                   [*GPU, MOTION], ['--use-angle=swiftshader'],
                   ['--proxy-server=synthetic'], ['--force-prefers-reduced-motion=1'],
                   [MOTION + '\n'], [*GPU, '--disable-gpu']]
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.assertRaises(LocalBrowserError):
                validated_environment_args({'environment_args': arguments})
        with self.assertRaises(LocalBrowserError):
            validated_environment_args(None)

    def test_candidate_never_guesses_missing_or_nonboolean_motion(self):
        for stable in ({}, {'screen.media': {}},
                       {'screen.media': {'(prefers-reduced-motion: reduce)': 'false'}},
                       {'screen.media': {'(prefers-reduced-motion: reduce)': 0}}):
            self.assertEqual(compatibility_candidate(stable, ['screen.media']), [])
        self.assertEqual(compatibility_candidate({}, ['fonts.metrics', 'devices.kinds']), [])


class EnvironmentContinuityTests(unittest.TestCase):
    def setUp(self):
        stable = {field: 'synthetic-original' for field in continuity._REQUIRED}
        stable.update({'context.secure': True, 'uaData.supported': False,
                       'devices.supported': True,
                       'devices.kinds': {'audioinput': 1, 'audiooutput': 1, 'videoinput': 0},
                       'webgl1.extensions': ['synthetic-extension'],
                       'webgl2.extensions': ['synthetic-extension'],
                       'webgl1.pixels': 'sha256:synthetic-original',
                       'screen.media': {'(prefers-reduced-motion: reduce)': False,
                                        '(pointer: fine)': True}})
        self.binding = {'synthetic': 'unchanged'}
        self.record = {'id': 'synthetic-id', '_native': {'synthetic': 'native-original'},
                       '_runtime': {'launch_args': [], 'core_major': '148'},
                       '_continuity': {'format': continuity.FORMAT,
                           'probe_version': continuity.PROBE_VERSION,
                           'binding': copy.deepcopy(self.binding), 'stable': stable,
                           'unstable': [], 'unavailable': []}}
        self.root = Path('synthetic-root')

    def sample(self, changes=None, *, missing=(), unstable=()):
        values = copy.deepcopy(self.record['_continuity']['stable'])
        values.update(changes or {})
        for field in missing:
            values.pop(field, None)
        return {'values': values, 'unstable': list(unstable), 'unavailable': []}

    def verify(self, samples, *, bindings=None):
        seen = []
        iterator = iter(samples)

        def probe(record, root):
            self.assertEqual(root, self.root)
            seen.append(copy.deepcopy(record['_runtime']['environment_args']))
            return next(iterator)

        options = {'side_effect': bindings} if bindings is not None else {'return_value': self.binding}
        with patch.object(continuity, 'binding_for', **options), \
                patch.object(continuity, 'probe_snapshot', side_effect=probe) as snapshot:
            try:
                result = continuity.verify_continuity(self.record, self.root)
            except LocalBrowserError as error:
                error.probe_args = seen
                error.probe_count = snapshot.call_count
                raise
        self.assertLessEqual(snapshot.call_count, 2)
        return result, seen

    def test_default_pass_ignores_stored_choice_without_mutating_record(self):
        self.record['_runtime']['environment_args'] = ['--proxy-server=synthetic']
        before = copy.deepcopy(self.record)
        result, seen = self.verify([self.sample()])
        self.assertTrue(result['passed'])
        self.assertEqual(result['environment_args'], [])
        self.assertEqual(seen, [[]])
        self.assertEqual(self.record, before)

    def test_motion_choice_is_derived_from_original_boolean_and_all_fields_match(self):
        for original, expected in ((False, NO_MOTION), (True, MOTION)):
            with self.subTest(original=original):
                self.record['_continuity']['stable']['screen.media']['(prefers-reduced-motion: reduce)'] = original
                changed = copy.deepcopy(self.record['_continuity']['stable']['screen.media'])
                changed['(prefers-reduced-motion: reduce)'] = not original
                before = copy.deepcopy(self.record)
                result, seen = self.verify([self.sample({'screen.media': changed}), self.sample()])
                self.assertEqual(result['environment_args'], [expected])
                self.assertEqual(seen, [[], [expected]])
                self.assertEqual(self.record, before)

    def test_gpu_extension_difference_uses_one_candidate_and_preserves_baseline(self):
        before = copy.deepcopy(self.record)
        result, seen = self.verify([self.sample({'webgl1.extensions': []}), self.sample()])
        self.assertEqual(result['environment_args'], GPU)
        self.assertEqual(seen, [[], GPU])
        self.assertEqual(self.record, before)

    def test_motion_and_drawing_have_one_combined_candidate(self):
        media = {'(prefers-reduced-motion: reduce)': True, '(pointer: fine)': True}
        result, seen = self.verify([self.sample({'screen.media': media, 'canvas.geometry': 'different'}), self.sample()])
        self.assertEqual(result['environment_args'], [NO_MOTION, *GPU])
        self.assertEqual(seen, [[], [NO_MOTION, *GPU]])

    def test_remaining_fonts_and_pixels_still_refuse_after_two_probes(self):
        before = copy.deepcopy(self.record)
        changes = {'webgl2.extensions': [], 'fonts.metrics': 'different-fonts',
                   'webgl1.pixels': 'different-pixels'}
        with self.assertRaises(LocalBrowserError) as raised:
            self.verify([self.sample(changes), self.sample({
                'fonts.metrics': 'different-fonts', 'webgl1.pixels': 'different-pixels'})])
        error = raised.exception
        self.assertEqual(error.changed_fields, ['fonts.metrics', 'webgl1.pixels'])
        self.assertEqual(error.environment_args, GPU)
        self.assertEqual(error.probe_count, 2)
        self.assertIn('字体', str(error))
        self.assertIn('绘图', str(error))
        self.assertNotIn('different-fonts', str(error))
        self.assertTrue(str(error).startswith('环境连续性检查'))
        self.assertEqual(self.record, before)

    def test_fonts_or_devices_alone_do_not_retry(self):
        for field in ('fonts.metrics', 'devices.kinds', 'audio.offline'):
            with self.subTest(field=field):
                if field not in self.record['_continuity']['stable']:
                    self.record['_continuity']['stable'][field] = 'synthetic-original'
                with self.assertRaises(LocalBrowserError) as raised:
                    self.verify([self.sample({field: 'different'})])
                self.assertEqual(raised.exception.probe_count, 1)
                self.assertEqual(raised.exception.environment_args, [])

    def test_original_missing_or_unstable_fields_refuse_without_retry(self):
        for sample in (self.sample(missing=['webgl1.pixels']),
                       self.sample(unstable=['webgl1.pixels'])):
            with self.subTest(sample=sample), self.assertRaises(LocalBrowserError) as raised:
                self.verify([sample])
            self.assertEqual(raised.exception.probe_count, 1)
            self.assertEqual(raised.exception.changed_fields, ['webgl1.pixels'])

    def test_candidate_missing_or_unstable_fields_never_pass(self):
        first = self.sample({'webgl1.extensions': []})
        for candidate in (self.sample(missing=['fonts.metrics']),
                          self.sample(unstable=['webgl1.pixels'])):
            with self.subTest(candidate=candidate), self.assertRaises(LocalBrowserError) as raised:
                self.verify([first, candidate])
            self.assertEqual(raised.exception.probe_count, 2)

    def test_binding_change_after_original_or_candidate_refuses(self):
        changed = {'synthetic': 'changed'}
        with self.assertRaises(LocalBrowserError) as raised:
            self.verify([self.sample({'webgl1.extensions': []})],
                        bindings=[self.binding, changed])
        self.assertEqual(raised.exception.probe_count, 1)
        self.assertEqual(raised.exception.changed_fields, ['binding'])
        with self.assertRaises(LocalBrowserError) as raised:
            self.verify([self.sample({'webgl1.extensions': []}), self.sample()],
                        bindings=[self.binding, self.binding, changed])
        self.assertEqual(raised.exception.probe_count, 2)
        self.assertEqual(raised.exception.changed_fields, ['binding'])

    def test_legacy_baseline_without_media_passes_and_never_forces_motion(self):
        self.record['_continuity']['stable'].pop('screen.media')
        result, seen = self.verify([self.sample()])
        self.assertEqual(result['environment_args'], [])
        self.assertEqual(seen, [[]])
        result, seen = self.verify([self.sample({'webgl1.extensions': []}), self.sample()])
        self.assertEqual(result['environment_args'], GPU)
        self.assertEqual(seen, [[], GPU])

    def test_derived_arguments_do_not_change_original_binding(self):
        record = copy.deepcopy(self.record)
        with patch.object(continuity, '_engine_binding', return_value={'synthetic': 'engine'}):
            original = continuity.binding_for(record, self.root)
            record['_runtime']['environment_args'] = [NO_MOTION, *GPU]
            self.assertEqual(continuity.binding_for(record, self.root), original)
            record['_runtime']['launch_args'] = ['--use-angle=d3d11']
            self.assertNotEqual(continuity.binding_for(record, self.root), original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
