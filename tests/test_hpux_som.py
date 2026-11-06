import io
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ablation.analyzers.binary_context import BinaryContext
from ablation.hpux import SomError, read_som
from ablation.hpux.cli import main
from ablation.hpux.som import parse_som

IBM_RE = Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE"))
SOM = IBM_RE / "analysis/Lotus123/42bdf512ad55cd70/20261106T195800Z-motif-som/input/123_motif"


class SomValidationTests(unittest.TestCase):
    def test_bad_magic(self):
        with self.assertRaises(SomError):
            parse_som(b"\0" * 128)

    def test_short_input(self):
        with self.assertRaises(SomError):
            parse_som(b"\x02\x10")


@unittest.skipUnless(SOM.is_file(), "SOM corpus unavailable")
class SomCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = read_som(SOM)

    def test_dynamic_layout(self):
        image = self.image
        self.assertEqual(image.sha256, "42bdf512ad55cd7071acecba13cdae3ca4da90118f3ed41b0e24cbdb55cac218")
        self.assertEqual(image.entry, 0x19C08)
        self.assertEqual(len(image.subspaces), 31)
        self.assertEqual(len(image.imports), 2321)
        self.assertEqual(len(image.exports), 819)
        self.assertEqual(len(image.dynamic_relocations), 3)
        self.assertEqual(len(image.dlt), 445)
        self.assertEqual(len(image.plt), 1876)
        self.assertEqual(len(image.unwind), 4586)
        self.assertEqual(sum(item.type == 3 and item.external for item in image.imports), 91)
        self.assertEqual(image.plt[28].proc_addr, 0x2F8DC)
        self.assertEqual(image.import_for_plt(image.plt[28]).name, "execlp")
        self.assertEqual(image.plt[172].proc_addr, 0x30094)
        self.assertEqual(image.import_for_plt(image.plt[172]).name, "systemcode_wrapper")

    def test_builtin_calls(self):
        calls = list(self.image.call_sites(0x2F9BC, 0x2F9E8))
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["name"], "execlp")
        self.assertEqual(calls[0]["call_va"], 0x2F9DC)
        self.assertEqual(calls[0]["owner_start"], 0x2F8F8)
        self.assertEqual(calls[1]["name"], "exit")
        execvp = next(call for call in self.image.call_sites(0x2D55C, 0x2D568) if call["name"] == "execvp")
        self.assertEqual(execvp["call_va"], 0x2D560)
        self.assertEqual(execvp["target_va"], 0x2D1B4)

    def test_mapping_bounds(self):
        self.assertEqual(self.image.bytes_at(0x16BA0, 3), b"sh\0")
        with self.assertRaises(SomError):
            self.image.bytes_at(0x1103C, 8)
        with self.assertRaises(SomError):
            list(self.image.instructions(0x2000000, 0x2000004))

    def test_binary_context(self):
        context = BinaryContext.load_or_build(str(SOM), force_rebuild=True)
        self.assertEqual(context.arch, "pa-risc")
        self.assertEqual(context.base_va, 0x1000)
        self.assertEqual(len(context.func_starts), 4586)
        self.assertEqual(len(context.plt), 91)
        self.assertEqual(len(context.call_edges), 28661)
        self.assertEqual(context.plt[0x2F8DC], "execlp")

    def test_cli(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["info", str(SOM)]), 0)
            self.assertEqual(main(["imports", str(SOM), "--external-code", "--json"]), 0)
            self.assertEqual(main(["disassemble", str(SOM), "0x2f9bc", "--length", "0x30", "--json"]), 0)
            self.assertEqual(main(["calls", str(SOM), "0x2f9bc", "--length", "0x30", "--json"]), 0)
            self.assertEqual(main(["functions", str(SOM), "--json"]), 0)


if __name__ == "__main__":
    unittest.main()
