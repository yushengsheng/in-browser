"""Bounded environment choices; the original fingerprint remains authoritative."""
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
