"""The public source export never includes diagnostic screenshots or data."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import build_release


class ReleaseBoundary(unittest.TestCase):
    def test_only_named_ui_and_resources_are_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            names=list(build_release.TOP)+['app/main.py','app/ui/app.js','app/ui/index.html',
                'app/ui/style.css','app/ui/README.md','app/resources/electron-main.js',
                'app/resources/crypto.worker.js','app/resources/defaults.json','app/resources/signature-verification-public.der']
            names+=['analysis/'+name for name in build_release.FIXTURES]
            excluded=['app/data/profile.bin','app/ui/output/playwright/private.png',
                'app/ui/.playwright-cli/session.json','app/resources/unexpected.json','analysis/private/credentials.py']
            for name in names+excluded:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('synthetic','utf-8')
            files={path.relative_to(root).as_posix() for path in build_release.source_files(root)}
            self.assertTrue(set(names)<=files)
            self.assertFalse(files.intersection(excluded))


if __name__=='__main__':unittest.main(verbosity=2)
