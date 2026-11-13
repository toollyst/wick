#!/usr/bin/env python3
"""Checks the Windows PowerShell scripts without Windows: compiles each one's C#.

Every `Add-Type` of a `.ps1` file in the repository is found with its source
(`-TypeDefinition`, or `-MemberDefinition` with `-Namespace` and `-Name`,
wrapped as Windows PowerShell 5.1 wraps it: `using System;` and `using
System.Runtime.InteropServices;`, then `public class <Name>` in `namespace
<Namespace>`), and compiled with Mono's C# compiler (`mcs`) as Windows
PowerShell 5.1 compiles it: C# 5 (the .NET Framework's csc.exe), referencing
`System.dll` and the `-ReferencedAssemblies` given. Each Add-Type alone, then
every Add-Type of one PowerShell session together, so a type defined twice
across them is caught as Add-Type would refuse it. An Add-Type inside a
here-string (a script the script writes and runs, as mitigation-audit.ps1's
control) is a session of its own. A compile error names the `.ps1` line.

It also refuses, per script: a function (or filter) defined twice in one
scope, which PowerShell takes silently, the later replacing the earlier; and
a `.ps1` with a byte outside ASCII and no UTF-8 byte order mark, which
Windows PowerShell 5.1 reads in the ANSI code page.

What it cannot check: whether the C# runs (a P/Invoke's DLL, entry point and
marshalling are Windows' own: Mono compiles a `DllImport` it never loads);
.NET Framework APIs Mono's class library lacks or has differently; the
PowerShell itself (its syntax, a command's or parameter's name, a variable
used before it is set: no PowerShell parser here); an Add-Type whose source
is made at run time, except the one listed in DYNAMIC; and what a double-quoted
here-string expands (refused when it has `$` or a backtick).

    python3 -I tools/windows/check-ps.py             # the repository's .ps1
    python3 -I tools/windows/check-ps.py --selftest  # this script's own test
"""

import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# An Add-Type whose source a script takes at run time: (script, the source
# expression) -> (the script it is taken from, the regular expression it is
# taken with, which this check applies to that script as the script does).
DYNAMIC = {
    ("tools/windows/jailer-test.ps1", "$source.Groups[1].Value"): (
        "tools/windows/boot-test.ps1",
        r"Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@",
    ),
}

# The directory a block's `#line` names its script under, so the
# compiler's message names it as the repository does.
LINE_ROOT = "/check-ps"

KEYWORD_BLOCKS = {"else", "try", "finally", "do", "trap", "begin", "process", "end", "dynamicparam", "clean", "catch"}


class Fail(Exception):
    pass


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


class Lexed:
    """What the lexer found in a script: its here-strings (start, end of the
    body, quote), its functions (name, line, scope), and the positions in
    code (outside strings and comments)."""

    def __init__(self):
        self.here = []
        self.functions = []
        self.code = []  # (start, end) spans of code text


def lex(text):
    """A PowerShell lexer as far as this check needs: comments, strings,
    here-strings, braces and `function`/`filter` definitions. A function's
    scope is the innermost enclosing function body or script block; the
    braces of if/else/foreach/while/switch/try/catch/finally and the like
    are statement blocks of the scope around them."""
    out = Lexed()
    i, n = 0, len(text)
    # The brace stack: each entry is the scope id the brace opens, or None
    # for a statement block.
    stack = []
    next_scope = [1]
    pending_function = None  # (name, line) waiting for its body's brace
    last_token = ""
    code_start = 0

    def scope():
        for s in reversed(stack):
            if s is not None:
                return s
        return 0

    def end_code(at):
        if at > code_start:
            out.code.append((code_start, at))

    def skip_dq(j):
        # A double-quoted string from after its quote; returns the index
        # after its closing quote. `$( ... )` may hold quotes of its own.
        while j < n:
            c = text[j]
            if c == "`":
                j += 2
                continue
            if c == '"':
                if j + 1 < n and text[j + 1] == '"':
                    j += 2
                    continue
                return j + 1
            if c == "$" and j + 1 < n and text[j + 1] == "(":
                j = skip_subexpr(j + 2)
                continue
            j += 1
        raise Fail("unterminated double-quoted string")

    def skip_subexpr(j):
        depth = 1
        while j < n:
            c = text[j]
            if c == "'":
                j = skip_sq(j + 1)
                continue
            if c == '"':
                j = skip_dq(j + 1)
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        raise Fail("unterminated $( )")

    def skip_sq(j):
        while j < n:
            if text[j] == "'":
                if j + 1 < n and text[j + 1] == "'":
                    j += 2
                    continue
                return j + 1
            j += 1
        raise Fail("unterminated single-quoted string")

    while i < n:
        c = text[i]
        if text.startswith("<#", i):
            end_code(i)
            j = text.find("#>", i + 2)
            if j < 0:
                raise Fail(f"line {line_of(text, i)}: unterminated <# comment")
            i = j + 2
            code_start = i
            continue
        if c == "#":
            end_code(i)
            j = text.find("\n", i)
            i = n if j < 0 else j
            code_start = i
            continue
        if c == "@" and i + 1 < n and text[i + 1] in "'\"" and text[i + 2 : i + 3] in ("\n", "\r"):
            q = text[i + 1]
            end_code(i)
            body = text.find("\n", i) + 1
            m = re.compile(r"(?m)^" + re.escape(q) + "@").search(text, body)
            if not m:
                raise Fail(f"line {line_of(text, i)}: unterminated here-string")
            end = m.start()
            out.here.append((body, end - 1 if end > body else body, q))
            i = m.end()
            code_start = i
            last_token = "string"
            continue
        if c == "'":
            end_code(i)
            i = skip_sq(i + 1)
            code_start = i
            last_token = "string"
            continue
        if c == '"':
            end_code(i)
            i = skip_dq(i + 1)
            code_start = i
            last_token = "string"
            continue
        if c == "{":
            if pending_function is not None:
                sid = next_scope[0]
                next_scope[0] += 1
                out.functions.append((pending_function[0], pending_function[1], scope()))
                pending_function = None
                stack.append(sid)
            elif last_token in (")", "]") or last_token.lower() in KEYWORD_BLOCKS:
                stack.append(None)
            else:
                sid = next_scope[0]
                next_scope[0] += 1
                stack.append(sid)
            last_token = "{"
            i += 1
            continue
        if c == "}":
            if not stack:
                raise Fail(f"line {line_of(text, i)}: a }} with no {{")
            stack.pop()
            last_token = "}"
            i += 1
            continue
        if c.isalpha() or c == "_":
            m = re.compile(r"[A-Za-z_][\w-]*").match(text, i)
            word = m.group(0)
            prev = text[i - 1] if i > 0 else "\n"
            if word.lower() in ("function", "filter") and prev not in "$-.:":
                f = re.compile(r"[ \t]+([\w:-]+)").match(text, m.end())
                if f:
                    pending_function = (f.group(1), line_of(text, i))
                    i = f.end()
                    last_token = "name"
                    continue
            last_token = word
            i = m.end()
            continue
        if c in ")]":
            last_token = c
        elif not c.isspace():
            last_token = c
        i += 1
    end_code(n)
    if stack:
        raise Fail(f"{len(stack)} {{ never closed")
    return out


ADD_TYPE = re.compile(r"(?i)\bAdd-Type\b")
PARAM = re.compile(r"-(TypeDefinition|MemberDefinition|Namespace|Name|ReferencedAssemblies|UsingNamespace|Language)\b", re.I)


def read_arg(text, j, end):
    """The argument at `j` (after spaces): a quoted string, a here-string, or
    a bare word or expression up to the next space; with its value (None
    when not literal), its kind and the index after it."""
    while j < end and text[j] in " \t":
        j += 1
    if text.startswith("@'", j) or text.startswith('@"', j):
        q = text[j + 1]
        body = text.find("\n", j) + 1
        m = re.compile(r"(?m)^" + re.escape(q) + "@").search(text, body)
        value = text[body : m.start()].rstrip("\r\n").replace("\r\n", "\n")
        return value, "here" + q, body, m.end()
    if text[j] == "'":
        k = j + 1
        while True:
            k = text.index("'", k)
            if text.startswith("''", k):
                k += 2
                continue
            break
        return text[j + 1 : k].replace("''", "'"), "sq", j + 1, k + 1
    m = re.compile(r"[^\s]+").match(text, j)
    return None, "word", j, m.end()


def add_types(text, path, start=0, end=None, session=None):
    """The Add-Types of `text[start:end]` (code, not strings), each a dict
    with its C# source, the line its source starts on and its references."""
    end = len(text) if end is None else end
    lexed = lex(text[start:end]) if start or end != len(text) else lex(text)
    found = []
    for a, b in lexed.code:
        for m in ADD_TYPE.finditer(text, start + a, start + b):
            # The command's arguments: up to the end of its line, or past a
            # here-string that starts on it.
            j = m.end()
            params = {}
            while True:
                eol = text.find("\n", j)
                eol = len(text) if eol < 0 else eol
                p = PARAM.match(text, j + len(text[j:eol]) - len(text[j:eol].lstrip(" \t")))
                if not p:
                    break
                value, kind, at, j = read_arg(text, p.end(), len(text))
                params[p.group(1).lower()] = (value, kind, at, text[p.end() : j].strip())
            found.append((m.start(), params))
    out = []
    for pos, params in found:
        line = line_of(text, pos)
        where = f"{path}:{line}"
        if "language" in params:
            raise Fail(f"{where}: Add-Type -Language: not checked here")
        refs = []
        if "referencedassemblies" in params:
            v = params["referencedassemblies"][3]
            refs = [r.strip().strip("'\"") for r in v.split(",")]
        if "typedefinition" in params:
            value, kind, at, raw = params["typedefinition"]
            if value is None:
                dyn = DYNAMIC.get((path, raw))
                if not dyn:
                    raise Fail(f"{where}: Add-Type -TypeDefinition {raw}: a source made at run time, not in DYNAMIC")
                out.append({"where": where, "dynamic": (raw, dyn), "refs": refs})
                continue
            if kind == 'here"' and ("$" in value or "`" in value):
                raise Fail(f"{where}: a double-quoted here-string with $ or a backtick: PowerShell expands it, not checked here")
            out.append({"where": where, "source": value, "line": line_of(text, at), "path": path, "refs": refs})
        elif "memberdefinition" in params:
            value, kind, at, raw = params["memberdefinition"]
            if value is None or "namespace" not in params or "name" not in params:
                raise Fail(f"{where}: Add-Type -MemberDefinition without a literal source, -Namespace and -Name")
            if kind in ('here"', "dq") and ("$" in value or "`" in value):
                raise Fail(f"{where}: a double-quoted source with $ or a backtick: PowerShell expands it, not checked here")
            ns, name = params["namespace"][3].strip("'\""), params["name"][3].strip("'\"")
            usings = ["System", "System.Runtime.InteropServices"]
            if "usingnamespace" in params:
                usings += [u.strip().strip("'\"") for u in params["usingnamespace"][3].split(",")]
            head = "".join(f"using {u};\n" for u in usings) + f"namespace {ns} {{\npublic class {name} {{\n"
            out.append({"where": where, "source": value, "line": line_of(text, at), "path": path, "refs": refs,
                        "head": head, "tail": "\n}\n}\n"})
        else:
            raise Fail(f"{where}: Add-Type with neither -TypeDefinition nor -MemberDefinition: not checked here")
    return out


def cs_file(block, d, k):
    """The block as a .cs file whose lines map back to the .ps1's."""
    f = os.path.join(d, f"b{k}.cs")
    src = block.get("head", "") + f'#line {block["line"]} "{os.path.join(LINE_ROOT, block["path"])}"\n' + block["source"] + "\n#line default\n" + block.get("tail", "")
    with open(f, "w", encoding="utf-8") as h:
        h.write(src)
    return f


def mcs(files, refs, d):
    tool = shutil.which("mcs")
    if not tool:
        raise Fail("no mcs (Mono's C# compiler) on PATH: install Mono (brew install mono); nothing was compiled")
    args = [tool, "-noconfig", "-langversion:5", "-target:library", "-nowarn:169,414,649,0168,0219",
            "-out:" + os.path.join(d, "out.dll"), "-r:System.dll"]
    args += [f"-r:{r if r.endswith('.dll') else r + '.dll'}" for r in refs]
    p = subprocess.run(args + files, capture_output=True, text=True, cwd=ROOT)
    errors = []
    for l in (p.stdout + p.stderr).splitlines():
        m = re.match(r"^(.*)\((\d+),(\d+)\): error (CS\d+): (.*)$", l)
        if m:
            where = m.group(1)
            if where.startswith(LINE_ROOT + os.sep):
                where = where[len(LINE_ROOT) + 1 :]
            errors.append(f"{where}:{m.group(2)}:{m.group(3)}: {m.group(4)}: {m.group(5)}")
        elif ": error " in l:
            errors.append(l)
    if p.returncode != 0 and not errors:
        errors = [(p.stdout + p.stderr).strip() or f"mcs exited {p.returncode}"]
    return errors


def check_script(path, text, scripts):
    """The problems of one script: its sessions' compiles, its functions and
    its encoding."""
    problems = []
    raw = text.encode("utf-8")
    if not raw.startswith(b"\xef\xbb\xbf") and any(b > 0x7f for b in raw):
        k = next(i for i, b in enumerate(raw) if b > 0x7f)
        problems.append(f"{path}:{raw[:k].count(b'\n') + 1}: a byte outside ASCII and no UTF-8 byte order mark: Windows PowerShell 5.1 reads it in the ANSI code page")
    lexed = lex(text)
    seen = {}
    for name, line, sc in lexed.functions:
        key = (name.lower(), sc)
        if key in seen:
            problems.append(f"{path}:{line}: function {name} defined again in the same scope (first at line {seen[key]}): the later replaces the earlier")
        else:
            seen[key] = line
    sessions = [(path, add_types(text, path))]
    for body, end, q in lexed.here:
        inner = text[body:end]
        # A script in a here-string: one with a line that starts with
        # Add-Type (not C# that names it in a comment).
        if q == "'" and re.search(r"(?im)^[ \t]*Add-Type\b", inner):
            sessions.append((f"{path}:{line_of(text, body)} (the script in the here-string)", add_types(text, path, body, end)))
    for name, blocks in sessions:
        with tempfile.TemporaryDirectory(prefix="check-ps-") as d:
            files, refs = [], set()
            for k, b in enumerate(blocks):
                if "dynamic" in b:
                    raw_expr, (src_path, rx) = b["dynamic"]
                    src_text = scripts.get(src_path)
                    if src_text is None:
                        problems.append(f"{b['where']}: its source, {src_path}, is not in the repository")
                        continue
                    if rx not in text:
                        problems.append(f"{b['where']}: DYNAMIC's regular expression for it is not in the script")
                    m = re.search(rx, src_text, re.S)
                    if not m:
                        problems.append(f"{b['where']}: {src_path} has no block its regular expression finds")
                        continue
                    pos = m.start(1)
                    b = {"where": b["where"], "source": m.group(1), "line": line_of(src_text, pos), "path": src_path, "refs": b["refs"]}
                files.append(cs_file(b, d, k))
                errs = mcs([files[-1]], b["refs"], d)
                problems += [f"{b['where']} (Add-Type): {e}" for e in errs]
                refs.update(b["refs"])
            if len(files) > 1:
                errs = mcs(files, sorted(refs), d)
                problems += [f"{name}: the session's Add-Types together: {e}" for e in errs if "CS0101" in e or "CS0111" in e]
    return problems


def scripts_of_repo():
    p = subprocess.run(["git", "ls-files", "*.ps1", "*.psm1"], capture_output=True, text=True, cwd=ROOT, check=True)
    out = {}
    for f in p.stdout.split():
        with open(os.path.join(ROOT, f), encoding="utf-8", newline="") as h:
            out[f] = h.read()
    return out


def selftest():
    good_cs = "using System;\nnamespace T {\n    public static class A { public static int F(int x) { return x; } }\n}"
    cases = [
        ("a good script", "function One { 1 }\nfunction Two { if ($true) { function In { } } }\n"
         "Add-Type -TypeDefinition @'\n" + good_cs + "\n'@\n"
         "Add-Type -Namespace T -Name M -MemberDefinition '[DllImport(\"kernel32.dll\")] public static extern int GetTickCount();'\n"
         "$s = { function One { } }\n", []),
        ("a type twice in one block", "Add-Type -TypeDefinition @'\nnamespace T {\n    public static class A { }\n\n    public static class A { }\n}\n'@\n",
         ["t.ps1:1 (Add-Type): t.ps1:5:", "CS0101"]),
        ("a type twice across two Add-Types", "Add-Type -TypeDefinition @'\n" + good_cs + "\n'@\nAdd-Type -TypeDefinition @'\n" + good_cs + "\n'@\n",
         ["session's Add-Types together", "CS0101"]),
        ("a member signature twice", "Add-Type -TypeDefinition @'\nnamespace T {\n  public static class A {\n    public static int F(int x) { return x; }\n    public static long F(int y) { return y; }\n  }\n}\n'@\n",
         ["t.ps1:1 (Add-Type): t.ps1:5:", "CS0111"]),
        ("C# 6 (string interpolation), which Windows PowerShell 5.1 does not compile",
         "Add-Type -TypeDefinition @'\nnamespace T { public static class A { public static string F(int x) { return $\"{x}\"; } } }\n'@\n", ["t.ps1:1 (Add-Type): t.ps1:2:"]),
        ("a function twice in one scope", "function One { }\nif ($x) { function one { } }\n", ["t.ps1:2: function one defined again"]),
        ("a function twice in one function", "function Outer {\n  function In { }\n  foreach ($a in $b) { function In { } }\n}\n", ["t.ps1:3: function In defined again"]),
        ("a byte outside ASCII", "# café\n", ["t.ps1:1: a byte outside ASCII"]),
        ("a source made at run time", "Add-Type -TypeDefinition $src\n", ["a source made at run time"]),
        ("a double-quoted here-string with $", "Add-Type -TypeDefinition @\"\nnamespace T { class A { string s = \"$x\"; } }\n\"@\n", ["PowerShell expands it"]),
        ("a brace in a string, a comment and a here-string", "function One { '{' ; \"}\" # {\n<# } #> @'\n}\n'@\n}\nfunction One { }\n",
         ["t.ps1:6: function One defined again"]),
    ]
    for name, text, want in cases:
        try:
            got = check_script("t.ps1", text, {})
        except Fail as e:
            got = [str(e)]
        if not want:
            assert got == [], (name, got)
        else:
            assert got, (name, "nothing found")
            joined = "\n".join(got)
            for w in want:
                assert w in joined, (name, w, got)
    # The block jailer-test.ps1 takes from boot-test.ps1 is found as it finds it.
    scripts = scripts_of_repo()
    for (path, _), (src, rx) in DYNAMIC.items():
        assert path in scripts and src in scripts, (path, src)
        assert re.search(rx, scripts[src], re.S), (src, rx)
    print(f"check-ps: selftest ok ({len(cases)} cases)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--selftest", action="store_true", help="test this script's own checks, and stop")
    ap.add_argument("files", nargs="*", help="the .ps1 files (default: every one git tracks)")
    opts = ap.parse_args()
    if opts.selftest:
        selftest()
        return 0
    scripts = scripts_of_repo()
    names = opts.files or sorted(scripts)
    def one(f):
        rel = os.path.relpath(os.path.abspath(f), ROOT) if opts.files else f
        if rel.startswith(".."):
            rel = os.path.abspath(f)
        text = scripts.get(rel)
        if text is None:
            with open(f, encoding="utf-8", newline="") as h:
                text = h.read()
        try:
            return check_script(rel, text, scripts), len(add_types(text, rel))
        except Fail as e:
            return [f"{rel}: {e}"], 0

    # One script per thread: the time is mcs's, one process per compile.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, names))
    problems = [p for r in results for p in r[0]]
    blocks = sum(r[1] for r in results)
    for p in problems:
        print(p)
    print(f"check-ps: {len(names)} scripts, {blocks} Add-Types in code: {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
