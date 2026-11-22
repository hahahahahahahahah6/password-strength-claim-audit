"""Static documentation and Python source analysis."""
import ast
import os
import re
from pathlib import Path
from .phrases import PASSWORDSTRENGTH, NOPASSWORDSTRENGTH, GENERIC_NAMES


def _pattern(phrases):
    return re.compile(r'(?<!\w)(?:' + '|'.join(re.escape(x) for x in sorted(phrases, key=lambda x: (-len(x), x))) + r')(?!\w)')

YES, NO = _pattern(PASSWORDSTRENGTH), _pattern(NOPASSWORDSTRENGTH)


def claims(text):
    lines = []
    fence = None
    for line in text.splitlines():
        m = re.match(r'^ {0,3}(`{3,}|~{3,})(.*)$', line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not m.group(2).strip():
                fence = None
            continue
        if m:
            fence = m.group(1)
            lines.append('')
        else:
            lines.append(line)
    yes, no = [], []
    for paragraph in re.split(r'\n\s*\n', '\n'.join(lines)):
        paragraph = re.sub(r'\s+', ' ', paragraph.lower().replace("n't", ' not').replace('-', ' '))
        no.extend(m.group() for m in NO.finditer(paragraph))
        paragraph = NO.sub(' ', paragraph)
        yes.extend(m.group() for m in YES.finditer(paragraph))
    return yes, no


def evidence(source):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return False
    imports, definitions, bound = {}, set(), set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definitions.add(node.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                imports[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for a in node.names:
                imports[a.asname or a.name] = node.module + '.' + a.name
        targets = []
        if isinstance(node, ast.Assign): targets = node.targets
        elif isinstance(node, ast.AnnAssign): targets = [node.target]
        elif isinstance(node, (ast.With, ast.AsyncWith)): targets = [i.optional_vars for i in node.items if i.optional_vars]
        for target in targets:
            bound.update(x.id for x in ast.walk(target) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store))
    def root(node):
        while isinstance(node, ast.Attribute): node = node.value
        return node.id if isinstance(node, ast.Name) else None
    def usable(name):
        return name in imports and name not in bound and name not in definitions
    def imported(node, path):
        return isinstance(node, ast.Name) and usable(node.id) and imports[node.id] == path
    def library_attr(node, attr, library):
        if not isinstance(node, ast.Attribute) or node.attr != attr or attr in definitions: return False
        base = root(node)
        return usable(base) and (imports[base] == library or imports[base].startswith(library + '.'))
    def allowed_attr(node):
        base = root(node)
        return node.attr not in definitions and not (base in imports and not usable(base))
    policy = stats = test = strength = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call): continue
        f = node.func
        if isinstance(f, ast.Name):
            if usable(f.id) and (imports[f.id] == 'zxcvbn.zxcvbn' or imports[f.id].split('.')[-1] in GENERIC_NAMES): return True
            policy |= imported(f, 'password_strength.PasswordPolicy')
            stats |= imported(f, 'password_strength.PasswordStats')
        elif isinstance(f, ast.Attribute):
            if library_attr(f, 'zxcvbn', 'zxcvbn'): return True
            if f.attr in GENERIC_NAMES and allowed_attr(f): return True
            policy |= library_attr(f, 'PasswordPolicy', 'password_strength')
            stats |= library_attr(f, 'PasswordStats', 'password_strength')
            if f.attr == 'from_names' and allowed_attr(f):
                policy |= imported(f.value, 'password_strength.PasswordPolicy') or library_attr(f.value, 'PasswordPolicy', 'password_strength')
            if allowed_attr(f):
                test |= f.attr == 'test'
                strength |= f.attr == 'strength'
    return bool((policy and test) or (stats and (test or strength)))


def audit(root, ignore=()):
    root = Path(root)
    if not root.is_dir() or not os.access(root, os.R_OK | os.X_OK): raise OSError('root is not a readable directory')
    ignored = [Path(x).as_posix().strip('/') for x in ignore]
    docs, production, tests = [], [], []
    def skip(rel):
        s = rel.as_posix()
        return any(s == x or s.startswith(x + '/') for x in ignored if x)
    def onerror(err): raise err
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        d = Path(directory)
        dirs[:] = sorted(x for x in dirs if not (d/x).is_symlink() and not skip((d/x).relative_to(root)))
        for name in sorted(files):
            path = d/name
            rel = path.relative_to(root)
            if path.is_symlink() or skip(rel): continue
            if (rel == Path('README.md') or ('docs' in rel.parts and path.suffix == '.md')):
                docs.append((rel.as_posix(), path.read_text(encoding='utf-8')))
            elif path.suffix == '.py':
                if any(x in rel.parts for x in ('fixtures', 'docs', 'examples')): continue
                target = tests if 'tests' in rel.parts or name.startswith('test_') or name.endswith('_test.py') else production
                if evidence(path.read_text(encoding='utf-8')): target.append(rel.as_posix())
    yes, no = [], []
    for path, content in docs:
        a, b = claims(content)
        yes.extend({'path': path, 'phrase': x} for x in a)
        no.extend({'path': path, 'phrase': x} for x in b)
    findings = []
    if yes and not production:
        findings.append({'id': 'documented-password-strength-claim-false', 'severity': 'MEDIUM' if tests else 'HIGH', 'claims': yes, 'evidence': tests})
    if no and production:
        findings.append({'id': 'documented-no-password-strength-claim-false', 'severity': 'HIGH', 'claims': no, 'evidence': production})
    return {'findings': findings, 'production_evidence': production, 'test_evidence': tests, 'claims': yes, 'denials': no}
