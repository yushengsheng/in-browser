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


class ContinuityFixture(unittest.TestCase):
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

    def verify(self, samples, *, bindings=None, allow_device_variance=None):
        seen = []
        self.probe_records = []
        iterator = iter(samples)

        def probe(record, root):
            self.assertEqual(root, self.root)
            seen.append(copy.deepcopy(record['_runtime']['environment_args']))
            self.probe_records.append(copy.deepcopy(record))
            return next(iterator)

        options = {'side_effect': bindings} if bindings is not None else {'return_value': self.binding}
        with patch.object(continuity, 'binding_for', **options), \
                patch.object(continuity, 'probe_snapshot', side_effect=probe) as snapshot:
            try:
                keywords = ({} if allow_device_variance is None else
                            {'allow_device_variance': allow_device_variance})
                result = continuity.verify_continuity(self.record, self.root, **keywords)
            except LocalBrowserError as error:
                error.probe_args = seen
                error.probe_count = snapshot.call_count
                raise
        self.assertLessEqual(snapshot.call_count, 2)
        return result, seen


class EnvironmentContinuityTests(ContinuityFixture):
    def test_boolean_and_numeric_type_changes_are_unstable_between_probe_reads(self):
        first = self.sample()
        second = self.sample({
            'devices.kinds': {'audioinput': True, 'audiooutput': 1, 'videoinput': 0},
            'screen.media': {'(prefers-reduced-motion: reduce)': 0, '(pointer: fine)': True},
        })
        merged = continuity._merge_samples(first, second)
        self.assertEqual(merged['unstable'], ['devices.kinds', 'screen.media'])
        self.assertNotIn('devices.kinds', merged['values'])
        self.assertNotIn('screen.media', merged['values'])
        self.assertIs(merged['values']['context.secure'], True)

    def test_default_pass_ignores_stored_choice_without_mutating_record(self):
        self.record['_runtime']['environment_args'] = ['--proxy-server=synthetic']
        before = copy.deepcopy(self.record)
        result, seen = self.verify([self.sample()])
        self.assertTrue(result['passed'])
        self.assertEqual(result['environment_args'], [])
        self.assertEqual(result['device_variance_fields'], [])
        self.assertEqual(result['verification_policy'], 'strict')
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


class VendorCompatibleContinuityTests(ContinuityFixture):
    def setUp(self):
        super().setUp()
        self.record['_runtime'].update(signature_provider='local-v1',
                                       launch_args=['--lang=zh-CN'])
        stable = self.record['_continuity']['stable']
        for field in ('canvas.geometry', 'canvas.text', 'webgl1.pixels', 'webgl2.pixels'):
            stable[field] = 'sha256:' + '1' * 64
        stable['fonts.metrics'] = [
            ['Arial', [200, 50, 2, 0, 198], [200, 50, 2, 0, 198], [200, 50, 2, 0, 198]],
            ['serif', [210, 51, 3, 0, 207], [210, 51, 3, 0, 207], [210, 51, 3, 0, 207]],
        ]
        stable['webgl1.extensions'] = ['EXT_blend_minmax', 'WEBGL_debug_renderer_info']
        stable['webgl2.extensions'] = ['EXT_color_buffer_float', 'WEBGL_debug_renderer_info']
        stable['audio.offline'] = 'sha256:' + '3' * 64
        self.variations = {
            'canvas.geometry': 'sha256:' + '2' * 64,
            'canvas.text': 'sha256:' + '2' * 64,
            'webgl1.pixels': 'sha256:' + '2' * 64,
            'webgl2.pixels': 'sha256:' + '2' * 64,
            'devices.kinds': {'audioinput': 2, 'audiooutput': 2, 'videoinput': 1},
            'screen.media': {'(prefers-reduced-motion: reduce)': True, '(pointer: fine)': True},
            'fonts.metrics': copy.deepcopy(stable['fonts.metrics']),
            'webgl1.extensions': ['WEBGL_debug_renderer_info'],
            'webgl2.extensions': ['WEBGL_debug_renderer_info'],
        }
        self.variations['fonts.metrics'][0][1][0] = 201.25

    def test_nine_stock_verified_variations_pass_one_original_probe_without_mutation(self):
        self.record['_runtime']['environment_args'] = [NO_MOTION, *GPU]
        before = copy.deepcopy(self.record)
        result, seen = self.verify([self.sample(self.variations)], allow_device_variance=True)
        self.assertTrue(result['passed'])
        self.assertEqual(result['verification_policy'], 'vendor-compatible-148')
        self.assertEqual(result['device_variance_fields'], sorted(self.variations))
        self.assertEqual(result['environment_args'], [])
        self.assertEqual(seen, [[]])
        self.assertEqual(self.record, before)
        self.assertEqual(self.probe_records[0]['_native'], before['_native'])
        self.assertEqual(self.probe_records[0]['_runtime']['launch_args'], before['_runtime']['launch_args'])

    def test_unchanged_device_has_an_empty_variance_report(self):
        result, seen = self.verify([self.sample()], allow_device_variance=True)
        self.assertTrue(result['passed'])
        self.assertEqual(result['verification_policy'], 'vendor-compatible-148')
        self.assertEqual(result['device_variance_fields'], [])
        self.assertEqual(result['environment_args'], [])
        self.assertEqual(seen, [[]])

    def test_default_and_explicit_strict_verification_still_require_exact_baseline(self):
        for enabled in (None, False, 1, 'true'):
            with self.subTest(enabled=enabled), self.assertRaises(LocalBrowserError) as raised:
                self.verify([self.sample(self.variations), self.sample(self.variations)],
                            allow_device_variance=enabled)
            self.assertEqual(raised.exception.probe_count, 2)
            self.assertEqual(raised.exception.changed_fields, sorted(self.variations))

    def test_other_core_or_signing_provider_remain_strict(self):
        for major, provider in (('124', 'local-v1'), ('150', 'local-v1'), ('148', 'vendor'), ('148', None)):
            with self.subTest(major=major, provider=provider):
                self.record['_runtime'].update(core_major=major, signature_provider=provider)
                with self.assertRaises(LocalBrowserError) as raised:
                    self.verify([self.sample(self.variations), self.sample(self.variations)],
                                allow_device_variance=True)
                self.assertEqual(raised.exception.probe_count, 2)

    def test_non_device_signals_are_not_accepted_alone_or_with_all_device_variations(self):
        changes = {
            'audio.offline': 'sha256:' + '4' * 64,
            'navigator.userAgent': 'synthetic-different-UA',
            'navigator.platform': 'synthetic-different-platform',
            'webgl1.identity': {'renderer': 'synthetic-different-renderer'},
            'screen.width': 999,
            'synthetic.extra': 'synthetic-different',
        }
        self.record['_continuity']['stable']['synthetic.extra'] = 'synthetic-original'
        self.record['_continuity']['stable']['webgl1.identity'] = {'renderer': 'synthetic-original'}
        for field, value in changes.items():
            for mixed in (False, True):
                with self.subTest(field=field, mixed=mixed):
                    changed = dict(self.variations) if mixed else {}
                    changed[field] = value
                    before = copy.deepcopy(self.record)
                    with self.assertRaises(LocalBrowserError) as raised:
                        self.verify([self.sample(changed), self.sample(changed)], allow_device_variance=True)
                    self.assertIn(field, raised.exception.changed_fields)
                    self.assertEqual(self.record, before)

    def test_device_field_missing_or_unstable_stops_before_any_candidate(self):
        for field in self.variations:
            for state in ('missing', 'unstable'):
                with self.subTest(field=field, state=state), self.assertRaises(LocalBrowserError) as raised:
                    sample = self.sample(self.variations, **{state: [field]})
                    self.verify([sample], allow_device_variance=True)
                self.assertEqual(raised.exception.probe_count, 1)
                self.assertEqual(raised.exception.changed_fields, [field])

    def test_candidate_must_have_every_field_stable_even_when_variance_is_enabled(self):
        first = self.sample({'webgl1.identity': {'renderer': 'synthetic-different-renderer'}})
        self.record['_continuity']['stable']['webgl1.identity'] = {'renderer': 'synthetic-original'}
        for field in self.variations:
            for state in ('missing', 'unstable'):
                with self.subTest(field=field, state=state), self.assertRaises(LocalBrowserError) as raised:
                    self.verify([first, self.sample(self.variations, **{state: [field]})],
                                allow_device_variance=True)
                self.assertEqual(raised.exception.probe_count, 2)
                self.assertEqual(raised.exception.changed_fields, [field])

    def test_binding_drift_rejects_before_probe_and_after_each_probe(self):
        changed = {'synthetic': 'changed'}
        cases = [([changed], [], 0),
                 ([self.binding, changed], [self.sample(self.variations)], 1),
                 ([self.binding, self.binding, changed],
                  [self.sample({'webgl1.identity': 'synthetic-different'}), self.sample()], 2)]
        self.record['_continuity']['stable']['webgl1.identity'] = 'synthetic-original'
        for bindings, samples, count in cases:
            with self.subTest(count=count), self.assertRaises(LocalBrowserError) as raised:
                self.verify(samples, bindings=bindings, allow_device_variance=True)
            self.assertEqual(raised.exception.probe_count, count)
            self.assertEqual(raised.exception.changed_fields, ['binding'])

    def test_malformed_device_values_cannot_be_accepted_as_variance(self):
        metrics = self.record['_continuity']['stable']['fonts.metrics']
        malformed_metrics = copy.deepcopy(metrics)
        malformed_metrics[0][1][0] = None
        boolean_metrics = copy.deepcopy(metrics)
        boolean_metrics[0][1][0] = True
        renamed_metrics = copy.deepcopy(metrics)
        renamed_metrics[0][0] = 'synthetic-renamed-font'
        infinite_metrics = copy.deepcopy(metrics)
        infinite_metrics[0][1][0] = float('inf')
        malformed = [
            ('canvas.geometry', 'sha256:short'),
            ('canvas.text', 'sha256:' + 'g' * 64),
            ('webgl1.pixels', {'status': 'unsupported'}),
            ('webgl2.pixels', 'sha256:' + 'A' * 64),
            ('devices.kinds', {'audioinput': True, 'audiooutput': 2, 'videoinput': 0}),
            ('devices.kinds', {'audioinput': -1, 'audiooutput': 1, 'videoinput': 0}),
            ('devices.kinds', {'audioinput': 1001, 'audiooutput': 1, 'videoinput': 0}),
            ('devices.kinds', {'audioinput': 1, 'audiooutput': 1}),
            ('devices.kinds', {'audioinput': 1, 'audiooutput': 1, 'videoinput': 0, 'other': 1}),
            ('fonts.metrics', []), ('fonts.metrics', malformed_metrics),
            ('fonts.metrics', boolean_metrics), ('fonts.metrics', renamed_metrics),
            ('fonts.metrics', list(reversed(metrics))), ('fonts.metrics', infinite_metrics),
            ('webgl1.extensions', ['WEBGL_debug_renderer_info', 'EXT_blend_minmax']),
            ('webgl1.extensions', ['EXT_blend_minmax', 'EXT_blend_minmax']),
            ('webgl2.extensions', [None]), ('webgl2.extensions', ['synthetic extension']),
            ('webgl2.extensions', ['X' * 129]),
            ('webgl2.extensions', ['EXT_' + str(index).zfill(4) for index in range(513)]),
            ('screen.media', {'(prefers-reduced-motion: reduce)': 1, '(pointer: fine)': True}),
            ('screen.media', {'(prefers-reduced-motion: reduce)': True}),
            ('screen.media', {'(prefers-reduced-motion: reduce)': True, '(pointer: fine)': False}),
        ]
        for field, value in malformed:
            with self.subTest(field=field, value=value):
                with self.assertRaises(LocalBrowserError) as raised:
                    changed = self.sample({field: value})
                    self.verify([changed, copy.deepcopy(changed)], allow_device_variance=True)
                self.assertIn(field, raised.exception.changed_fields)

    def test_boolean_type_changes_cannot_hide_as_equal_device_values(self):
        metrics = copy.deepcopy(self.record['_continuity']['stable']['fonts.metrics'])
        metrics[0][1][3] = False
        changes = {
            'devices.kinds': {'audioinput': True, 'audiooutput': 1, 'videoinput': 0},
            'screen.media': {'(prefers-reduced-motion: reduce)': 0, '(pointer: fine)': True},
            'fonts.metrics': metrics,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                with self.assertRaises(LocalBrowserError) as raised:
                    actual = self.sample({field: value})
                    self.verify([actual, copy.deepcopy(actual)], allow_device_variance=True)
                self.assertIn(field, raised.exception.changed_fields)

    def test_invalid_baseline_shape_cannot_authorize_valid_actual_device_value(self):
        for field, value in (('canvas.geometry', 'sha256:invalid-original'),
                             ('devices.kinds', {'audioinput': False, 'audiooutput': 1, 'videoinput': 0}),
                             ('fonts.metrics', [['Arial', None, None, None]]),
                             ('webgl1.extensions', ['synthetic invalid original']),
                             ('screen.media', {'(prefers-reduced-motion: reduce)': 0, '(pointer: fine)': True})):
            with self.subTest(field=field):
                original = self.record['_continuity']['stable'][field]
                try:
                    self.record['_continuity']['stable'][field] = value
                    with self.assertRaises(LocalBrowserError) as raised:
                        actual = self.sample({field: self.variations[field]})
                        self.verify([actual, copy.deepcopy(actual)], allow_device_variance=True)
                    self.assertIn(field, raised.exception.changed_fields)
                finally:
                    self.record['_continuity']['stable'][field] = original


if __name__ == '__main__':
    unittest.main(verbosity=2)
