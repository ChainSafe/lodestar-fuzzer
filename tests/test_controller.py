import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("controller", ROOT / "controller.py")
assert SPEC is not None and SPEC.loader is not None
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


class ManifestTests(unittest.TestCase):
    def test_load_and_select_manifest_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fuzz_root = Path(temporary)
            executable = fuzz_root / "zig-out" / "bin" / "fuzz-one"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"binary")
            executable.chmod(0o755)
            corpus = fuzz_root / "corpus" / "one-cmin"
            corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"seed")
            manifest = fuzz_root / "targets.tsv"
            manifest.write_text(
                "schema\tgroup\ttarget\texecutable\tcmin\tmax_input_len\n"
                "2\tssz\tone\tzig-out/bin/fuzz-one\tcorpus/one-cmin\t4\n",
                encoding="utf-8",
            )

            targets = controller.load_targets(manifest, fuzz_root)

            self.assertEqual([target.name for target in targets], ["one"])
            self.assertEqual(controller.select_targets(targets, "ssz,one"), targets)

    def test_rejects_extra_manifest_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fuzz_root = Path(temporary)
            manifest = fuzz_root / "targets.tsv"
            manifest.write_text(
                "schema\tgroup\ttarget\texecutable\tcmin\tmax_input_len\n"
                "2\tssz\tone\tbin\tcorpus\t4\t\n",
                encoding="utf-8",
            )

            with self.assertRaises(controller.ControllerError):
                controller.load_targets(manifest, fuzz_root)


class CorpusTests(unittest.TestCase):
    def test_copy_by_hash_deduplicates_identical_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            first.write_bytes(b"same")
            second.write_bytes(b"same")

            count = controller.copy_by_hash([first, second], root / "corpus")

            self.assertEqual(count, 1)
            stored = list((root / "corpus").iterdir())
            self.assertEqual(stored[0].read_bytes(), b"same")


if __name__ == "__main__":
    unittest.main()
