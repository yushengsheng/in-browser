"""Measure stock/local production background probes in one synthetic package.

This diagnostic never enrolls or changes the saved baseline. Use it on the source
machine as well as targets when interpreting per-core device differences.
"""
import argparse
import copy
import json
from pathlib import Path
import sys
import traceback

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
    report = {'success': False, 'core': args.core, 'synthetic': True,
              'diagnostic_only': True, 'checks': {}}
    fixture = storage = record = saved = data = None
    try:
        import verify_portable_fixture as fixture
        import verify_login_storage as storage
        import compare_vendor_runtime as comparison
        from configuration import Configuration
        from core_specs import supports_major
        comparison._require(supports_major(args.core)
                            and fixture.ROOT.resolve() == ROOT.resolve()
                            and comparison.ROOT.resolve() == ROOT.resolve())
        fixture.CORE = args.core
        _, record, data, profile = fixture.load_fixture(ROOT, allow_session_cookie=True)
        saved = storage._protection(record, fixture, ROOT)
        original_runtime = copy.deepcopy(record['_runtime'])
        configuration = Configuration(data)
        signature = fixture._inside(ROOT / 'vendor-signature.bin', ROOT)
        comparison._vendor_signature(signature, configuration, saved['native'])
        stock, files, directories = comparison._stock_engine(record, fixture, ROOT)
        report['checks']['stock_core_exactly_restored'] = True
        comparison._background_comparison(record, data, ROOT, stock, signature,
                                          configuration, fixture, report)
        _, current, _, _ = fixture.load_fixture(ROOT, allow_session_cookie=True)
        report['checks'].update(storage._protection_checks(current, saved, fixture, ROOT))
        report['checks']['runtime_unchanged'] = current['_runtime'] == original_runtime
        report['checks']['stock_core_unchanged'] = comparison._runtime_inventory(
            stock.parent, args.core, directories) == (files, directories)
        report['success'] = all(report['checks'].values())
    except Exception as error:
        report.update(error_type=type(error).__name__, frames=[{'file': Path(frame.filename).name,
            'line': frame.lineno} for frame in traceback.extract_tb(error.__traceback__)[-8:]])
    destination = ROOT / 'analysis/reports/all-core-background-comparison.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return int(not report['success'])


if __name__ == '__main__':
    raise SystemExit(main())
