"""Pure in-memory regression checks; do not import .NET or initialize data."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


ENTRY = Path(__file__).resolve().parents[1] / 'app/local_browser.pyw'


class ManagerWebviewClose(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = ast.parse(ENTRY.read_text('utf-8'))
        guard = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                     and node.name == '_guard_initial_webview_cleanup')
        namespace = {}
        exec(compile(ast.Module(body=[guard], type_ignores=[]), str(ENTRY), 'exec'), namespace)
        cls.guard = staticmethod(namespace[guard.name])

    def browser(self, core=None):
        browser = SimpleNamespace(webview=SimpleNamespace(CoreWebView2=core, Dispose=Mock()),
                                  clear_user_data=Mock(return_value='original-result'))
        return browser, SimpleNamespace(native=SimpleNamespace(browser=browser))

    def test_early_close_disposes_only_this_control_without_original_cache_cleanup(self):
        browser, window = self.browser()
        sibling, _ = self.browser()
        original, sibling_cleanup = browser.clear_user_data, sibling.clear_user_data
        self.guard(window)
        browser.webview.Dispose.assert_not_called()
        self.assertIsNone(browser.clear_user_data())
        browser.webview.Dispose.assert_called_once_with()
        original.assert_not_called()
        self.assertIs(sibling.clear_user_data, sibling_cleanup)
        sibling.webview.Dispose.assert_not_called()

    def test_initialization_finishing_after_hook_uses_original_cleanup_and_result(self):
        browser, window = self.browser()
        original = browser.clear_user_data
        self.guard(window)
        browser.webview.CoreWebView2 = object()
        self.assertEqual(browser.clear_user_data(), 'original-result')
        original.assert_called_once_with()
        browser.webview.Dispose.assert_not_called()

    def test_initialized_cleanup_error_is_not_swallowed_or_replaced(self):
        browser, window = self.browser(object())
        original = browser.clear_user_data
        failure = RuntimeError('synthetic original cleanup failure')
        original.side_effect = failure
        self.guard(window)
        with self.assertRaises(RuntimeError) as caught:
            browser.clear_user_data()
        self.assertIs(caught.exception, failure)
        original.assert_called_once_with()
        browser.webview.Dispose.assert_not_called()

    def test_uninitialized_dispose_error_is_not_swallowed(self):
        browser, window = self.browser()
        original = browser.clear_user_data
        failure = RuntimeError('synthetic disposal failure')
        browser.webview.Dispose.side_effect = failure
        self.guard(window)
        with self.assertRaises(RuntimeError) as caught:
            browser.clear_user_data()
        self.assertIs(caught.exception, failure)
        original.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
