"""Run the unchanged production gate twice for one authenticated synthetic core."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--core', required=True)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({'executed': False}))
        return 0
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools')]
    from core_specs import supports_major
    if not supports_major(args.core):
        raise ValueError('Unsupported synthetic core')
    import verify_portable_fixture as fixture
    import verify_login_storage as storage
    fixture.CORE = args.core
    return storage.main(['--execute', '--verify'])


if __name__ == '__main__':
    raise SystemExit(main())
