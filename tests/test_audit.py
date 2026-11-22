import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from password_strength_claim_audit.audit import audit, claims, evidence
from password_strength_claim_audit.phrases import PASSWORDSTRENGTH, NOPASSWORDSTRENGTH, GENERIC_NAMES

class AuditTests(unittest.TestCase):
    def test_phrases(self):
        self.assertEqual((len(set(PASSWORDSTRENGTH)), len(set(NOPASSWORDSTRENGTH)), len(set(GENERIC_NAMES))), (50, 24, 24))
        for phrase in PASSWORDSTRENGTH:
            with self.subTest(phrase=phrase): self.assertTrue(claims(phrase)[0])
        for phrase in NOPASSWORDSTRENGTH:
            with self.subTest(phrase=phrase): self.assertEqual(claims(phrase), ([], [phrase]))
        self.assertEqual(claims('```\npassword strength\n```\n\n`password strength`')[0], ['password strength'])
        self.assertEqual(claims("doesn't check password strength"), ([], ['does not check password strength']))

    def test_routes(self):
        cases=['from zxcvbn import zxcvbn as z\nz()', 'import zxcvbn as z\nz.zxcvbn()', 'from password_strength import PasswordPolicy as P\nP().test()', 'import password_strength as p\np.PasswordPolicy.from_names().test()', 'from password_strength import PasswordStats as S\nS().strength()', 'import password_strength as p\np.PasswordStats()\nx.test()', 'x.check_password_strength()', 'from x import score_password as s\ns()']
        cases += ['x.'+name+'()' for name in GENERIC_NAMES]
        for code in cases:
            with self.subTest(code=code): self.assertTrue(evidence(code))

    def test_non_routes(self):
        cases=['import zxcvbn', 'zxcvbn()', 'x.zxcvbn()', 'PasswordPolicy()', 'PasswordStats()', 'strength()', 'test()', 'x.strength()', 'x.test()', 'from password_strength import PasswordPolicy\nPasswordPolicy()', 'from password_strength import PasswordPolicy\nPasswordPolicy.from_names()', 'from password_strength import PasswordStats\nPasswordStats()', 'policy.password()', 'stats.entropy_bits', 'stats.entropy_density', 'stats.weakness_factor', 'check_password()', 'bcrypt.hashpw()', 'argon2.hash()', 'hashlib.sha256()', 'passlib.hash()', 'secrets.token_urlsafe()', 'secrets.choice(a)', 'len(password)', 're.match(pattern, password)', 'email.validate()', 'phone.validate()', 'extract()', 'sms.send()', 'email.send()', 'decode_qr()', 'subprocess.run(["zxcvbn"])', '"check password strength"', 'score_password()', 'from x import score_password\ndef score_password(): pass\nscore_password()', 'import zxcvbn as z\nz = other\nz.zxcvbn()', 'import password_strength as p\nwith thing() as p: pass\np.PasswordPolicy().test()', 'def broken(:']
        for code in cases:
            with self.subTest(code=code): self.assertFalse(evidence(code))

    def test_findings_and_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); (p/'README.md').write_text('check password strength')
            self.assertEqual(audit(p)['findings'][0]['severity'], 'HIGH')
            (p/'tests').mkdir(); (p/'tests/test_x.py').write_text('x.score_password()')
            self.assertEqual(audit(p)['findings'][0]['severity'], 'MEDIUM')
            (p/'app.py').write_text('x.score_password()')
            self.assertFalse(audit(p)['findings'])
            (p/'README.md').write_text('does not check password strength')
            self.assertEqual(audit(p)['findings'][0]['severity'], 'HIGH')
            self.assertFalse(audit(p, ['app.py'])['findings'])

    def test_module_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); (p/'README.md').write_text('password strength')
            (p/'a.py').write_text('from password_strength import PasswordPolicy\nPasswordPolicy()')
            (p/'b.py').write_text('x.test()')
            self.assertEqual(audit(p)['findings'][0]['severity'], 'HIGH')

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); (p/'README.md').write_text('password strength')
            command=[sys.executable, '-m', 'password_strength_claim_audit']
            result=subprocess.run(command+['audit',tmp,'--json'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2); self.assertEqual(json.loads(result.stdout)['findings'][0]['severity'], 'HIGH')
            self.assertEqual(subprocess.run(command+['--bad'], capture_output=True).returncode, 1)
            self.assertEqual(subprocess.run(command+['--version'], capture_output=True, text=True).stdout.strip(), '0.1.0')

if __name__ == '__main__': unittest.main()
