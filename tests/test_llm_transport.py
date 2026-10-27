import json
import subprocess
import unittest
from types import SimpleNamespace

from ablation.analyzers.llm_analyst.transport import AblationTransport


class TransportTests(unittest.TestCase):
    def test_cascade_and_sdk_response(self):
        calls = []

        class Messages:
            def create(self, **kwargs):
                calls.append(kwargs)
                return SimpleNamespace(
                    content=[SimpleNamespace(text='{"action":"done"}')],
                    usage=SimpleNamespace(input_tokens=11, output_tokens=7),
                )

        client = SimpleNamespace(messages=Messages())
        transport = AblationTransport(sdk_client=client)
        response = transport.complete("system", "prompt", task="name_function")
        self.assertEqual(response.text, '{"action":"done"}')
        self.assertEqual(response.model, "claude-haiku-4-5")
        self.assertEqual((response.input_tokens, response.output_tokens), (11, 7))
        self.assertEqual(calls[0]["max_tokens"], 1024)

    def test_explicit_model_and_token_limit(self):
        transport = AblationTransport(model="custom-model", cli_runner=self._cli_success)
        response = transport.complete("system", "prompt", task="exploit_chain", max_tokens=64)
        self.assertEqual(response.model, "custom-model")
        with self.assertRaises(ValueError):
            transport.complete("system", "prompt", max_tokens=0)

    def test_cli_uses_isolated_workspace_and_disallowed_tools(self):
        transport = AblationTransport(cli_runner=self._cli_success)
        response = transport.complete("replace defaults", "investigate", task="patch_analysis")
        self.assertEqual(response.text, "completed")
        self.assertEqual(self.cmd[:3], ["claude", "-p", "-"])
        self.assertIn("Bash", self.cmd[self.cmd.index("--disallowedTools") + 1])
        self.assertEqual(self.prompt, "investigate")
        self.assertNotIn("CLAUDE.md", self.cwd)

    def test_cli_error_and_empty_output_propagate(self):
        transport = AblationTransport(cli_runner=lambda *args: subprocess.CompletedProcess(args[0], 2, "", "denied"))
        with self.assertRaisesRegex(RuntimeError, "exit 2"):
            transport.complete("system", "prompt")
        transport = AblationTransport(cli_runner=lambda *args: subprocess.CompletedProcess(args[0], 0, "  ", ""))
        with self.assertRaisesRegex(RuntimeError, "empty output"):
            transport.complete("system", "prompt")

    def test_cli_error_envelope_and_missing_result(self):
        transport = AblationTransport(cli_runner=lambda *args: subprocess.CompletedProcess(args[0], 0, json.dumps({"type": "result", "is_error": True, "result": "failed"}), ""))
        with self.assertRaisesRegex(RuntimeError, "is_error"):
            transport.complete("system", "prompt")
        transport = AblationTransport(cli_runner=lambda *args: subprocess.CompletedProcess(args[0], 0, "[]", ""))
        with self.assertRaisesRegex(RuntimeError, "no result event"):
            transport.complete("system", "prompt")

    @staticmethod
    def _cli_success(cmd, prompt, cwd, timeout):
        TransportTests.cmd = cmd
        TransportTests.prompt = prompt
        TransportTests.cwd = cwd
        return subprocess.CompletedProcess(cmd, 0, json.dumps([{"type": "result", "result": "completed"}]), "")


if __name__ == "__main__":
    unittest.main()
