"""Both ELF command entry points must reject the same ambiguous inputs."""
import subprocess
import sys
import unittest


class ELFCLIInputTests(unittest.TestCase):
    def command(self, module, *arguments):
        cmd = [sys.executable, '-m', module, '/nonexistent.elf', '--function', 'example']
        if module.endswith('check_elf_preemption'):
            cmd += ['--region-base', '0x8000', '--region-size', '8']
        return subprocess.run(cmd+list(arguments), capture_output=True, text=True)

    def test_both_entry_points_reject_duplicate_registers(self):
        for module in ('smpreempt.exploration.step_elf_pmp',
                       'smpreempt.exploration.check_elf_preemption'):
            with self.subTest(module=module):
                result = self.command(module, '--reg', 'x1=1', '--reg', '1=2')
                self.assertEqual(result.returncode, 2)
                self.assertIn('duplicate register assignment', result.stderr)

    def test_both_entry_points_reject_overlapping_memory_assignments(self):
        for module in ('smpreempt.exploration.step_elf_pmp',
                       'smpreempt.exploration.check_elf_preemption'):
            with self.subTest(module=module):
                result = self.command(module, '--mem32', '0x8000=1', '--mem8', '0x8001=2')
                self.assertEqual(result.returncode, 2)
                self.assertIn('overlapping initial memory assignments', result.stderr)
