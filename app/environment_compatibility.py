"""Bounded stock-verified device variations and strict compatibility choices."""
import math
import re

from local_state import LocalBrowserError


_REDUCED_MOTION = '--force-prefers-reduced-motion'
_NO_REDUCED_MOTION = '--force-prefers-no-reduced-motion'
_D3D11 = ('--use-angle=d3d11', '--ignore-gpu-blocklist')
_ALLOWED_ARGUMENTS = frozenset({
    (), (_REDUCED_MOTION,), (_NO_REDUCED_MOTION,), _D3D11,
    (_REDUCED_MOTION, *_D3D11), (_NO_REDUCED_MOTION, *_D3D11),
})
_DRAWING_FIELDS = frozenset({'canvas.geometry', 'canvas.text'} | {
    f'webgl{version}.{field}'
    for version in (1, 2)
    for field in ('supported', 'identity', 'extensions', 'limits', 'precision',
                  'attributes', 'pixels')
})
_VENDOR_FIELDS = frozenset({
    'canvas.geometry', 'canvas.text', 'fonts.metrics', 'devices.kinds', 'screen.media',
    'webgl1.extensions', 'webgl1.pixels', 'webgl2.extensions', 'webgl2.pixels',
})


def _device_value_valid(field, original, actual):
    if field in ('canvas.geometry', 'canvas.text', 'webgl1.pixels', 'webgl2.pixels'):
        return all(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value)
                   for value in (original, actual))
    if field == 'devices.kinds':
        return all(isinstance(value, dict)
                   and set(value) == {'audioinput', 'audiooutput', 'videoinput'}
                   and all(type(count) is int and 0 <= count <= 1000 for count in value.values())
                   for value in (original, actual))
    if field == 'screen.media':
        motion = '(prefers-reduced-motion: reduce)'
        return (isinstance(original, dict) and isinstance(actual, dict)
                and motion in original and original.keys() == actual.keys()
                and all(type(value) is bool for value in (*original.values(), *actual.values()))
                and all(original[key] == actual[key] for key in original if key != motion))
    if field in ('webgl1.extensions', 'webgl2.extensions'):
        return all(isinstance(value, list) and len(value) <= 512
                   and all(isinstance(name, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,127}', name)
                           for name in value)
                   and value == sorted(set(value)) for value in (original, actual))
    if field == 'fonts.metrics':
        def valid(value):
            return (isinstance(value, list) and 0 < len(value) <= 512
                    and all(isinstance(row, list) and len(row) == 4
                            and isinstance(row[0], str) and 0 < len(row[0]) <= 256
                            and all(isinstance(metrics, list) and len(metrics) == 5
                                    and all(type(number) in (int, float) and math.isfinite(number)
                                            for number in metrics) for metrics in row[1:])
                            for row in value))
        return (valid(original) and valid(actual)
                and [row[0] for row in original] == [row[0] for row in actual])
    return False


def vendor_device_differences(runtime, original, actual):
    """Only 148 has cross-device stock/local evidence; other builds stay strict.

    Call after validating the unchanged native payload, engine binding and a
    complete stable probe. Neither recorded values nor launch options change.
    """
    if runtime.get('signature_provider') != 'local-v1' or str(runtime.get('core_major')) != '148':
        return []
    return sorted(field for field in _VENDOR_FIELDS
                  if field in original and field in actual and original[field] != actual[field]
                  and _device_value_valid(field, original[field], actual[field]))


def validated_environment_args(runtime):
    """Only return an owned copy of one exact, ordered compatibility choice."""
    arguments = runtime.get('environment_args', []) if isinstance(runtime, dict) else None
    if (not isinstance(arguments, list)
            or any(not isinstance(argument, str) for argument in arguments)
            or tuple(arguments) not in _ALLOWED_ARGUMENTS):
        error = LocalBrowserError('环境连续性检查未通过（environment_args），未启动真实窗口；原资料和基线已保留。')
        error.changed_fields = ['environment_args']
        error.environment_args = []
        raise error
    return list(arguments)


def compatibility_candidate(stable, changed_fields):
    """Derive at most one candidate from original baseline values and differences."""
    arguments = []
    changed = set(changed_fields)
    media = stable.get('screen.media')
    if 'screen.media' in changed and isinstance(media, dict):
        motion = media.get('(prefers-reduced-motion: reduce)')
        if type(motion) is bool:
            arguments.append(_REDUCED_MOTION if motion else _NO_REDUCED_MOTION)
    if changed & _DRAWING_FIELDS:
        arguments.extend(_D3D11)
    return validated_environment_args({'environment_args': arguments})
