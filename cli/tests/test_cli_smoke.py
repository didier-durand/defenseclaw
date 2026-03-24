import os
import unittest

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner


class CliSmokeTests(unittest.TestCase):
    def test_main_import_no_circular_dependency(self):
        import defenseclaw.main as main_mod
        self.assertTrue(hasattr(main_mod, "cli"))

    def test_top_level_help_works_without_init(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Usage:", result.output)
        self.assertIn("Commands:", result.output)
        self.assertIn("init", result.output)
        self.assertIn("skill", result.output)

    def test_init_help_works(self):
        from defenseclaw.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Initialize DefenseClaw environment", result.output)


if __name__ == "__main__":
    unittest.main()
