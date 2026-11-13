"""Keep ordinary path identities while using Windows extended paths for I/O."""
import ntpath
import os
from pathlib import Path


def absolute_path(path):
    value = os.fsdecode(path)
    if os.name == 'nt':
        value = value.replace('/', '\\')
        if value[:8].casefold() == '\\\\?\\unc\\':
            value = '\\\\' + value[8:]
        elif value.startswith('\\\\?\\'):
            value = value[4:]
            if not ntpath.isabs(value) or not ntpath.splitdrive(value)[0].endswith(':'):
                raise ValueError('Unsupported Windows path namespace')
        elif value.startswith('\\\\.\\'):
            raise ValueError('Unsupported Windows path namespace')
        value = ntpath.abspath(value)
    else:
        value = os.path.abspath(value)
    return Path(value)


def io_path(path):
    """Return an ephemeral I/O path; never store or compare its prefix."""
    value = absolute_path(path)
    if os.name != 'nt':
        return value
    text = str(value)
    return Path('\\\\?\\UNC\\' + text[2:] if text.startswith('\\\\') else '\\\\?\\' + text)


def resolved_path(path):
    return absolute_path(io_path(path).resolve())


def tree_paths(path):
    for item in io_path(path).rglob('*'):
        yield absolute_path(item)
