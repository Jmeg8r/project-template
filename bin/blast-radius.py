#!/usr/bin/env python3
"""
WHAT: Given the files a PR changed, find the files that DEPEND on them.
WHY:  The gate reviews "what did this change break", not "what is wrong with the repo".
      That requires the change plus its dependents — the blast radius. Reviewing the diff
      alone misses broken callers; reviewing the whole project is infeasible (astgl-articles
      is 372,600 lines) and turns the gate into noise that gets clicked through.

THE FAILURE MODE THIS GUARDS AGAINST
      A dependency sweep that finds nothing looks exactly like a change with no dependents.
      Both print "0 dependents" and both let the PR sail through. So this tool refuses to
      report a clean result it cannot justify: it runs a POSITIVE CONTROL first — a search
      for a token it has already proven exists in the tree — and if that control does not
      come back, it reports UNKNOWN and exits non-zero instead of "no dependents".
      Every run states how many files it scanned.

A NOTE ON THE EXAMPLE PATHS BELOW
      Every illustrative filename below carries an angle-bracketed segment --
      `<dir>/<name>.ts`, never a plausible real path. That is a rule about the whole
      class, not a patch on one example. This file deploys byte-identical into
      consuming repos and matches other files by LITERAL REFERENCE, so any path or
      basename spelled out here makes THIS file a permanent phantom dependent of the
      real file that happens to bear that name -- the same inflation the basename rule
      below exists to prevent, self-inflicted, shipped to every consumer.
      Spelling the examples out as full `src/`-rooted paths did exactly that to four
      real files in mcp-techkb. Shortening them by one leading segment only moved the
      problem to a repo laid out that way (Codex [P2] on PR #45) -- which is why the
      rule is a placeholder FORM and not a shorter path. No tracked file is named with
      angle brackets, so nothing in these examples can match one. This paragraph obeys
      its own rule: it describes those paths rather than spelling them.
      Measured, not asserted: a repo carrying one real file per basename-shaped token
      in this file produces zero phantoms for every plausible source name. Two matches
      survive and are deliberate. A file named exactly `.d.ts` hits the extension
      constants, which cannot be spelled any other way; and a SECOND file named like
      this one hits the usage block via the bare Python stem token, which the deployed
      copy never triggers because a file is excluded from its own dependents. Neither
      is a name a real tree carries.

MATCHING
      Python imports are resolved structurally (module path -> importers).
      JS/TS imports are resolved structurally too, and MUST be: under NodeNext an
      importer writes the COMPILED specifier for a SOURCE file — `from './<dir>/<name>.js'`
      names `<dir>/<name>.ts` — so the text never contains the path or basename of the
      file on disk, and literal matching reported ZERO dependents for a TypeScript
      change with eleven real importers (mcp-techkb, Codex [P1] on PR #13, 2026-08-29).
      A gate that cannot see any caller can issue a clean review of a breaking change,
      which is the exact failure this tool exists to prevent. Resolution is against the
      IMPORTER's own directory, not by rewriting the extension into another bare token:
      a sibling `'./<name>.js'` is only unambiguous once you know which directory it
      sits in — this repo's consumers have two same-named modules under one src/ tree.
      Everything else — shell, YAML, markdown, docs — is matched by literal reference to
      the file's path or basename, because in this repo a workflow referencing <dir>/<name>.sh
      or a runbook documenting it IS a dependent: change the flags and those break.
      The bare BASENAME counts only when it names exactly one file across the tracked
      tree plus the targets themselves: in a repo where every breaking-note archive
      ships the same handful of filenames, a file that merely names one of them is not
      referring to THIS one. Counting those matches inflated a 7-file PR to 42
      "dependents" / 411,912 request bytes — past the review broker's 400,000-byte cap
      (astgl-articles PR #58, 2026-08-27). The targets count too because a DELETED
      target no longer appears in git ls-files: judged against tracked files alone, a
      deleted, previously-unique basename read as count 0 and its dependents were
      silently missed — or handed to a surviving same-name file (Codex [P2] on that
      same PR's review). Path-qualified references always count, and Python import
      tokens are unchanged.

Usage:
  bin/blast-radius.py FILE [FILE...]           # dependents of these files
  bin/blast-radius.py --changed-from BASE      # dependents of files changed vs BASE
  bin/blast-radius.py --json FILE...           # machine-readable
"""
from __future__ import annotations

# IMPORT-PATH GUARD, before any shadowable import. Running bin/blast-radius.py puts
# bin/ FIRST on sys.path, and this file is deployed into bin/ of every consuming repo —
# so a PR that merely ADDS bin/json.py (or subprocess.py, re.py, pathlib.py) has that
# module execute inside this script, which the gate job runs with BROKER_TOKEN and a
# forge token in scope. Pinning the workflow's checkout to a reviewed SHA guards nothing
# if the script's own imports resolve into the PR's tree. Only `sys` is touched before
# the guard: it is a builtin and cannot be shadowed. String ops rather than os.path,
# because importing os here would itself be shadowable.
import sys

# Suffix comparison, not equality: on macOS sys.path[0] is the RESOLVED directory
# (/private/var/...) while __file__ keeps the symlinked form (/var/...), so a plain
# `==` silently never matches and the guard quietly does nothing. Caught by running the
# hijack fixture from a tempfile.TemporaryDirectory (unresolved) rather than a
# pre-resolved one -- the upstream copy this came from compares by equality and has the
# same hole, it just never ran a test that could see it.
_script_dir = __file__.rsplit("/", 1)[0] if "/" in __file__ else "."
_p0 = sys.path[0] if sys.path else None
if _p0 is not None and (_p0 in ("", ".", _script_dir)
                        or _p0.endswith(_script_dir) or _script_dir.endswith(_p0)):
    sys.path.pop(0)
del _script_dir, _p0

import ast
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

# Never read these as text, and never call them dependents.
SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".docx", ".xlsx",
               ".woff", ".woff2", ".ico", ".zst", ".db", ".sqlite"}
MAX_FILE_BYTES = 512_000

# Files whose relative import specifiers get resolved structurally. Everything not in
# this set stays on literal-reference matching.
JS_FAMILY_SUFFIX = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
# Files that ARE an importable Python module, in both directions: whose own path yields
# a module name, and whose imports get read. Both, because they are one claim -- a stub
# is imported by the same name as the module it describes, so resolving one direction
# without the other reports zero dependents for every changed stub.
PY_FAMILY_SUFFIX = {".py", ".pyi"}
# A module named by a STRING at a loader call rather than by the import grammar. The
# quotes make the name unambiguous at ANY length, which is what makes this the right
# route for a name too short for word_token's floor -- lowering that floor instead was
# measured and is not viable: word-boundary "re" hits 16 of 30 tracked files here and
# "db" 19 of 50 in mcp-techkb.
DYNAMIC_IMPORT_CALLS = {"import_module", "__import__"}
# Which loader each MODULE provides, and therefore which `<ns>.<attr>` spellings name
# one. A table over the whole input domain rather than an equality check on a single
# spelling: `<ns>.__import__` was rejected outright, so an importer of a one- or
# two-character module written that way disappeared entirely -- the name is below
# word_token's floor and the literal tokens hold only the filename, so the target
# reported ZERO dependents, the exact failure this resolver exists to prevent (Codex
# [P2] on mcp-techkb PR #18, 2026-08-29).
#
# `importlib.__import__` is in here because it EXISTS -- verified against the
# interpreter: present, same five-argument signature, and it really imports. Codex
# named only the `builtins` spelling; the same miss in code that already imports
# importlib is the other half of the same class, and fixing the reported instance
# alone would have left it.
#
# DELIBERATELY NOT ACCEPTED, all three for the same reason -- there is no BINDING to
# check, only a value to track:
#   getattr(<ns>, "__import__")     a computed attribute name, which is the answer
#                                   this resolver already gives every computed name
#                                   (an interpolated JS specifier, import_module(f())).
#   <ns>.__dict__["__import__"],    subscripts of an opaque container; resolving them
#   sys.modules["builtins"].…       is value-flow analysis, the same class of tool
#                                   _loader_bindings already declines for scope.
#   __builtins__.__import__         verified against the interpreter: `__builtins__`
#                                   is a DICT in any imported module and a module only
#                                   in __main__, so outside a directly-run script that
#                                   spelling is an AttributeError, not an import. It is
#                                   also a CPython implementation detail no import
#                                   statement ever binds, so nothing could be proven
#                                   about it even in the case where it works.
#
# SELF-REFERENCE, measured not assumed: the key "builtins" is a word_token match, so a
# repo file named builtins.py now counts THIS file as a dependent where it did not
# before (measured: PRE [] -> POST [bin/blast-radius.py]). Accepted, and already the
# documented policy -- importlib.py, ast.py and json.py have the same property today
# for the same reason, and word_token below states why a stem shadowing a preloaded
# stdlib module is knowingly not excluded. The name cannot be spelled any other way
# without making the binding check unreadable, and the direction is over-report.
LOADER_MODULE_ATTRS = {
    "importlib": frozenset({"import_module", "__import__"}),
    "builtins": frozenset({"__import__"}),
}
# PEP 561: a stub-only distribution ships `<name>-stubs/`, and what it provides stubs
# FOR is `<name>` -- that is the only name an importer ever writes. Carrying the
# directory name through unchanged derives a form with a hyphen in it, which is not a
# valid identifier and so can never match any import: the target resolved to nothing
# usable and reported zero dependents (Codex [P2] on PR #58, 2026-08-29). Stripping it
# cannot introduce a false match for the same reason -- the un-stripped form was
# unmatchable to begin with.
STUBS_DIR_SUFFIX = "-stubs"
# What an importer WRITES -> the source extensions NodeNext maps it onto. A table,
# not a blanket: the mapping is per-extension in BOTH directions. '.mjs' must reach a
# '.d.mts' declaration, and must NOT claim a same-stem '.ts' that TypeScript would
# never resolve it to — a false dependent is the same bug class as the bare-basename
# over-matching above. (Codex [P2] on sovereign-forge PR #44 caught the missing
# declaration extensions; the over-match was the other half of the same blanket.)
JS_SPEC_TO_SOURCE = {
    ".js":  (".ts", ".tsx", ".d.ts"),
    ".jsx": (".tsx", ".d.ts"),
    ".mjs": (".mts", ".d.mts"),
    ".cjs": (".cts", ".d.cts"),
}
# Source extensions reachable from an EXTENSIONLESS specifier (bundler/CJS resolution,
# where './foo' and './foo/index' are both legal). NodeNext requires the extension, so
# this branch never fires for it.
JS_SOURCE_EXT = (".ts", ".tsx", ".mts", ".cts", ".d.ts", ".d.mts", ".d.cts",
                 ".js", ".jsx", ".mjs", ".cjs")
# Any quoted relative path, including backticks: `await import(`./<name>.js`)` is a
# static specifier like any other, and missing it means silently dropping a real
# caller -- the failure this resolver exists to prevent. The delimiter is captured and
# back-referenced so an opening quote only closes on its own kind. Deliberately not a
# JavaScript parser: this catches import/export/require/dynamic-import in one rule, and
# over-matching a relative path in an ordinary string literal is consistent with how
# this tool already treats a mere reference to a file as a dependency.
REL_SPEC_RE = re.compile(r"""(['"`])(\.\.?(?:/[^'"`\n]*)?)\1""")
# A template literal with an interpolation resolves to nothing at rest, so there is no
# path to check -- skip rather than invent one out of the literal `${...}` text.
INTERPOLATION = "${"


def repo_root() -> Path:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=True)
    return Path(out.stdout.strip())


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                         capture_output=True, text=True, check=True)
    return [root / p for p in out.stdout.split("\0") if p]


# Sentinel for a file that SHOULD be inspectable — not a known-binary suffix, not a
# symlink — but could not be read: too large, unreadable, or not UTF-8. That is NOT a
# clean skip. It might import or reference a changed target, so an empty blast radius
# computed over it is UNKNOWN, not "no dependents" — the same call every other check in
# this tool makes. Returned distinctly from None so the caller can tell "nothing to see
# here" from "I could not look".
SKIPPED = object()


def readable_text(p: Path):
    """str content, None for a genuine non-text or symlink skip, or SKIPPED for a
    would-be-text file that could not be read (the caller fails closed on SKIPPED)."""
    if p.suffix.lower() in SKIP_SUFFIX:
        return None
    # A tracked SYMLINK is never read and never followed. read_text() follows it, so a
    # link committed into the repo made this sweep read whatever it pointed at — and in
    # CI that includes .git/config, which holds the forge token. The content would then
    # be searched for target tokens and the path reported as a "dependent", putting the
    # link's own name next to data it should never have opened. A symlink's TEXT is not
    # a dependency signal in any case: what it references is a path, not an import.
    try:
        if p.is_symlink() or not p.is_file():
            return None
    except OSError:
        return None
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return SKIPPED  # a large TEXT file may still be a dependent
        return p.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return SKIPPED  # unreadable or non-UTF-8, but not a known binary type


def literal_tokens(rel: str, basename_counts: dict[str, int]) -> list[str]:
    """How a file refers to this one by NAME — path or basename, matched as a substring.

    The bare basename is a usable reference only when it is unique among tracked files
    plus the targets themselves (see MATCHING above for the measured failure when it is
    not, and why deleted targets are part of the count). The >2 filter keeps a 1-2 char
    name from matching half the tree.

    Python MODULE names are no longer in here. They used to be, matched by substring, and
    that forced a choice with no good answer: keep the >2 filter and a real `io.py` finds
    no importers at all, or drop it and "io" matches ratio, region, and every other word
    containing those letters — flooding the radius until the broker's file cap truncates
    a real importer away. Both were measured (Codex, 2026-08-22). Exact matching against
    AST-extracted imports dissolves the tradeoff, so module forms moved to
    module_dotted_forms() and this function stayed literal.
    """
    p = Path(rel)
    toks = {rel}
    if basename_counts.get(p.name, 0) == 1:
        toks.add(p.name)
    # DOTTED module forms stay literal tokens; only the BARE stem left. The flood was
    # always the stem -- "bench" matching "benchmark" in a .gitignore -- never
    # "benchmark.ollama-perf.bench", which is specific enough to be safe as a substring.
    # And dropping the dotted forms entirely broke every module reference that never
    # reaches an AST: `python -m plugins.foo` in a workflow YAML, an
    # importlib.import_module("plugins.foo") string, an import inside a .pyi (not parsed
    # as .py), and any source using syntax newer than the scanner's own Python, where
    # ast.parse fails and literal matching is the only remaining signal. Measured: a
    # fixture with those callers went from three dependents to ZERO -- an empty blast
    # radius on a breaking change, the exact failure this tool exists to prevent
    # (Codex [P1] on PR #54).
    #
    # Only forms containing a dot: the bare last component is the stem, which is the one
    # that floods. A suffix like "plugins.foo" also lets a `python -m plugins.foo` match
    # a file at src/plugins/foo.py, where the full path form would not.
    toks |= {f for f in module_dotted_forms(rel) if "." in f}
    return [t for t in toks if len(t) > 2]


def _strip_stubs(parts: list[str]) -> list[str]:
    """PEP 561's `<name>-stubs` -> `<name>`, stated once so both sides agree.

    Applied to the TARGET's own path and to an IMPORTER's package alike. Normalizing
    only one side is worse than normalizing neither: the two derivations then disagree
    and a stub package's own sibling imports match nothing at all (Codex [P2], third
    round on PR #58). The suffix cannot be part of a real module name -- a hyphen is
    not valid in an identifier -- so this can only ever turn an unmatchable form into
    a matchable one.
    """
    n = len(STUBS_DIR_SUFFIX)
    return [c[:-n] if c.endswith(STUBS_DIR_SUFFIX) else c for c in parts]


def _module_parts(p: Path) -> list[str]:
    """The path components a module's dotted name is built from.

    Shared so module_dotted_forms() and word_token() cannot disagree about what a file
    is called -- they derived it separately, and a rule added to one silently did not
    reach the other.
    """
    parts = list(p.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]  # the package IS its directory
    if p.suffix == ".pyi":
        parts = _strip_stubs(parts)
    return [c for c in parts if c]


def module_dotted_forms(rel: str) -> set[str]:
    """Every dotted name a Python file could be imported by. Empty for a non-.py file.

    <dir>/<name>.py -> {"<name>", "<dir>.<name>", ...} — every suffix of the path, because
    which directory is the source root (src/, the repo root, a package dir) is not known
    here. Safe to be generous now that these are matched EXACTLY against the importer's
    real AST imports rather than searched for as substrings; as substrings the same set
    would be exactly the flood described above.

    <pkg>/__init__.py -> the forms for the PACKAGE, with __init__ dropped: `import pkg`
    never writes it, so the file's own stem names nothing.
    """
    p = Path(rel)
    if p.suffix not in PY_FAMILY_SUFFIX:
        return set()
    parts = _module_parts(p)
    return {".".join(parts[i:]) for i in range(len(parts)) if parts[i:]}


def word_token(rel: str) -> str | None:
    """The BARE module name for a .py file, or None when there is not a usable one.

    Kept apart from literal_tokens because it is matched on WORD BOUNDARIES rather than
    as a substring. That distinction is the whole fix: as a raw substring "bench" matched
    the word "benchmark" in a .gitignore and produced 85 phantom dependents from one
    target, while dropping it entirely lost every non-AST reference -- `python -m widget`
    in a workflow, importlib.import_module("widget"), a .pyi import, or any source
    ast.parse cannot read. Boundary matching keeps the reference and refuses the
    substring: "widget" matches `python -m widget` and not the word "widgets".
    """
    p = Path(rel)
    if p.suffix not in PY_FAMILY_SUFFIX:
        return None
    parts = _module_parts(p)
    if not parts:
        return None
    name = parts[-1]
    # The >2 minimum is the same one literal_tokens applies, and for the same reason: a
    # 1-2 character name is a WORD in ordinary prose, so even boundary-matched it floods.
    # Measured: a 1-char a.py matched 15 of 17 tracked files in this repo, which under
    # the broker's 120-file cap would displace the genuine callers it was meant to find
    # (Codex [P2], round 3). Such a module is not left unresolved -- AST matching finds
    # `import a` exactly, and that path has no length floor. What is given up is only the
    # NON-AST reference to a 1-2 char module (a bare `python -m a` in a YAML), where a
    # text search for that name could never have been trustworthy anyway.
    #
    # KNOWINGLY NOT EXCLUDED: names that shadow an already-imported stdlib module. A repo
    # file named io.py does not really shadow `io`, which is in sys.modules before any
    # repo code runs, so its importers are arguably phantoms (Codex [P2], round 2). An
    # earlier revision excluded them via frozenset(sys.modules) and had to be reverted:
    # that set is VERSION-DEPENDENT -- `io` is preloaded on Python 3.9, 3.12 and 3.13 but
    # NOT on 3.14 -- so the same PR resolved a different blast radius depending on which
    # interpreter CI happened to install. review-broker.py requires a merge gate to return
    # the same verdict for the same head_sha, and a resolver whose answers move with the
    # runtime cannot deliver that. Over-reporting is also the safe direction here: a
    # phantom dependent is reviewable noise, a missed one is a silent breaking change.
    if len(name) <= 2:
        return None
    return name


def _arg(call: ast.Call, pos: int, kw: str) -> ast.expr | None:
    """One argument of a call, written either positionally or by keyword."""
    if len(call.args) > pos:
        return call.args[pos]
    for keyword in call.keywords:
        if keyword.arg == kw:
            return keyword.value
    return None


def _dict_value(node: ast.expr | None, key: str) -> ast.expr | None:
    """The value a DICT LITERAL gives `key`, or None when it is not one or lacks it."""
    if not isinstance(node, ast.Dict):
        return None
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


def _literal_str(node: ast.expr | None) -> str | None:
    """The string a node IS, or None. A computed name resolves to nothing at rest --
    the same answer this resolver already gives an interpolated JS specifier."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _module_loader(fn: ast.Attribute, modules_ns: dict[str, set[str]]) -> str | None:
    """Which loader `<ns>.<attr>` names, or None when it names none.

    The accepted shape stated once, over the whole domain: `<ns>` must be a name an
    import statement IN THIS FILE bound to a loader module, and `<attr>` must be a
    loader that module actually provides (LOADER_MODULE_ATTRS). Both halves are needed
    and neither is new -- the module check is the same one that keeps a project's own
    registry helper named `import_module` from being read as a Python import, and the
    attribute check is what an equality test against a single spelling was standing in
    for. Shared by the call site and the alias loop so the two cannot drift: an alias
    of a spelling the caller accepts must be accepted too, or `imp = builtins.__import__`
    is a miss the direct call is not.

    ANY of the name's candidate modules satisfies it, which is what makes the set a set.
    A file is read per FILE, not per lexical scope (see _loader_bindings), so one name
    can carry two bindings -- `import importlib as loader` at module level and
    `import builtins as loader` inside a function. Recording only the last one ast.walk
    reached let the inner binding erase the outer, and the top-level
    `loader.import_module("q")` was then rejected for naming an attribute `builtins`
    does not provide: a real importer of a one-character module DISAPPEARED, which is
    the very failure the qualified-spelling fix was written to close (Codex [P2] on
    PR #66, caught before merge; measured pre-fix ['shadowed.py'] -> post-fix []).
    Union, not scope analysis, for the reason _loader_bindings already gives: resolving
    it properly is Python name-binding analysis, and the residual error here is an
    over-match, the direction this resolver accepts everywhere else.
    """
    if not isinstance(fn.value, ast.Name):
        return None
    mods = modules_ns.get(fn.value.id)
    if not mods or not any(fn.attr in LOADER_MODULE_ATTRS[m] for m in mods):
        return None
    return fn.attr


def _loader_bindings(tree: ast.AST) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Which names in this file actually refer to a module loader, and WHICH ones.

    Both values map a bound name to a SET, and for one reason: a file is read per
    FILE, not per lexical scope, so one name can carry two bindings at once and the
    later must not erase the earlier. Keeping a single value collapsed them by
    ast.walk order and silently discarded a real call -- once on the module axis and
    again on the kind axis after only the first was fixed (Codex [P2], both rounds on
    PR #66). The residual error is an over-match, which is the direction this resolver
    accepts everywhere else.

    The second value maps a bound name to the loaders it names, not merely to the fact
    that it names one. The two loaders take different arguments -- `import_module`
    resolves a relative name against `package`, `__import__` against `level` -- so a
    set of names loses exactly the thing the caller needs: an alias of `__import__`
    read as an `import_module` looks at the wrong argument and drops the call
    (Codex [P2], second round on PR #58).

    Matching any call whose last identifier happens to be `import_module` treats a
    project's own registry helper as a Python import, and for a short target that
    invents a dependent out of unrelated code. `from .importlib import import_module`
    is likewise a package's OWN helper, which is why the level is checked and not just
    the module name. `__import__` needs no binding: it is a builtin, always in scope.

    Read per FILE, not per lexical scope, so a name deliberately shadowing importlib
    (a parameter or local of that name) is still read as the loader. Declined rather
    than overlooked: resolving that is Python name-binding analysis -- scope stacks,
    parameters, comprehensions, class bodies -- which is a different tool from a
    dependency heuristic, and the failure is an over-match, the direction this
    resolver accepts everywhere else.
    """
    # bound name -> every loader MODULE it names. A SET because one name can be bound
    # twice in a file read per-file rather than per-scope, and the later binding must
    # not erase the earlier one.
    modules_ns: dict[str, set[str]] = {}
    # bound name -> every loader KIND it names. A set for the same reason modules_ns
    # is one, and it must be BOTH: fixing only the module map left the identical
    # collapse one axis over, where `from importlib import import_module as load` and
    # an inner `from builtins import __import__ as load` reduced `load` to whichever
    # ast.walk reached last (Codex [P2], second round on PR #66).
    kinds: dict[str, set[str]] = {"__import__": {"__import__"}}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                # `import importlib.util` binds the ROOT name, not the dotted one.
                root = a.name.split(".")[0]
                if root in LOADER_MODULE_ATTRS:
                    modules_ns.setdefault(a.asname or root, set()).add(root)
        elif (isinstance(node, ast.ImportFrom) and not node.level
              and node.module in LOADER_MODULE_ATTRS):
            for a in node.names:
                # The attribute names ARE the kind strings, so no mapping is needed --
                # and reading the table rather than one hard-coded name is what lets
                # `from builtins import __import__ as imp` bind, the same way
                # `from importlib import import_module as im` already did. Unaliased it
                # would work by luck, since `kinds` is seeded with the builtin; aliased
                # it was a miss.
                if a.name in LOADER_MODULE_ATTRS[node.module]:
                    kinds.setdefault(a.asname or a.name, set()).add(a.name)
    # `load = importlib.import_module` then `load("<mod>")` is an ordinary plugin
    # pattern, and missing it is a MISS -- the dangerous direction -- because a name
    # short enough to need this route is excluded from word_token by design (Codex
    # [P2] on PR #58, 2026-08-29). Iterated to a fixed point so a second hop
    # (`a = importlib.import_module` then `b = a`) resolves too; bounded by the number
    # of assignments, since each pass either adds a name or stops.
    # AnnAssign as well as Assign: `load: Callable = importlib.import_module` is an
    # ordinary annotated alias, and reading only the bare form dropped it.
    for _ in range(len(kinds) + 8):
        grew = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, v = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, v = [node.target], node.value
            else:
                continue
            if isinstance(v, ast.Attribute):
                k = _module_loader(v, modules_ns)
                new_kinds = {k} if k else set()
            elif isinstance(v, ast.Name):
                new_kinds = kinds.get(v.id, set())   # carries the ORIGIN's kinds along
            else:
                new_kinds = set()
            if not new_kinds:
                continue
            for tgt in targets:
                # UNION, not first-wins: an alias rebound in another scope adds a
                # candidate rather than being ignored, the same way modules_ns now
                # accumulates. Termination is unchanged -- `grew` is set only when a
                # kind is genuinely added, and there are two kinds in total.
                if isinstance(tgt, ast.Name) and not new_kinds <= kinds.get(tgt.id, set()):
                    kinds.setdefault(tgt.id, set()).update(new_kinds)
                    grew = True
        if not grew:
            break
    return modules_ns, kinds


def _with_fromlist(node: ast.Call, parts: list[str], fname: str) -> set[str]:
    """The module a call names, plus any submodules a literal fromlist asks for.

    `__import__("<pkg>", fromlist=("<mod>",))` imports <pkg>.<mod>; import_module has
    no fromlist. A non-literal entry, and the "*" wildcard, name nothing at rest --
    the same answer every other computed name here gets.
    """
    if not parts:
        return set()
    base = ".".join(parts)
    out = {base}
    if fname != "__import__":
        return out
    fl = _arg(node, 3, "fromlist")
    if isinstance(fl, (ast.Tuple, ast.List, ast.Set)):
        out.update(f"{base}.{v}" for v in (_literal_str(e) for e in fl.elts)
                   if v and v != "*")
    return out


def _dynamic_module(node: ast.Call, here: list[str],
                    modules_ns: dict[str, set[str]],
                    kinds: dict[str, set[str]]) -> set[str]:
    """The modules a loader CALL names. Empty when it names nothing resolvable.

    A SET, not one name, because `__import__` takes a FROMLIST:
    `__import__("<pkg>", fromlist=("<mod>",))` imports `<pkg>.<mod>`, and recording
    only `<pkg>` loses the submodule that is the actual subject of the call. For a
    name short enough to need this route the source never contains the qualified form
    either, so it was a miss with nothing to fall back on (Codex [P2], fifth round on
    PR #58).

    A loader is recognised by WHICH LOADER IT IS, never by how it was spelled --
    `__import__`, `builtins.__import__`, `importlib.__import__` and an alias of any of
    them are one call taking one set of arguments. Accepting only the bare name and
    `importlib.import_module` made a module-qualified `__import__` fall through, and
    for a one- or two-character module that is not a degradation but a disappearance:
    nothing else in the file spells the name (Codex [P2] on mcp-techkb PR #18).

    The two loaders spell "relative" differently and neither infers the caller's
    package the way an import statement does. Verified against the interpreter rather
    than assumed: `import_module(".<mod>")` with no package raises TypeError, and
    `__import__(".<mod>")` looks for a module literally so named. Resolving either
    against the importer's own location would invent a dependent for a call that
    cannot load anything.
    """
    fn = node.func
    if isinstance(fn, ast.Attribute):
        # The table decides, not an equality test against one spelling. Which loader
        # the attribute names then flows through unchanged: `<ns>.__import__` gets the
        # level/globals/fromlist contract below, `<ns>.import_module` the package one.
        # An attribute names exactly one loader -- the attribute IS the name -- so this
        # side never has more than one candidate however many modules `<ns>` may mean.
        fname = _module_loader(fn, modules_ns)
        names = {fname} if fname else set()
    elif isinstance(fn, ast.Name):
        names = kinds.get(fn.id, set())   # the loaders it NAMES, not the name it got
    else:
        return set()
    # Resolved under EACH candidate and unioned. A name carrying two kinds is a
    # per-file read of two scopes, and picking one of them is how the outer call got
    # discarded; trying both costs an over-match on a file that already had two
    # loaders bound to one name, and misses nothing.
    return set().union(*(_loader_call(node, here, f) for f in names)) if names else set()


def _loader_call(node: ast.Call, here: list[str], fname: str) -> set[str]:
    """The modules ONE loader kind reads out of this call. Split from the candidate
    selection above so a name bound to both kinds can be resolved under each."""
    # `is None`, not falsiness: a literal EMPTY name is meaningful. `from . import
    # <mod>` compiles to `__import__("", globals(), locals(), ("<mod>",), 1)`, and a
    # loader written that way is an ordinary importer -- conflating "no literal
    # argument" with "the empty string" dropped it before the level or the fromlist
    # was ever read (Codex [P2], sixth round on PR #58). Verified against the
    # interpreter: that call imports <pkg>.<mod>, and the same call at level 0 is a
    # ValueError, which is why empty is accepted ONLY with a positive level.
    mod = _literal_str(_arg(node, 0, "name"))
    if mod is None:
        return set()

    if fname == "__import__":
        # Relative only via `level`, its fifth argument -- never by a leading dot.
        if mod.startswith("."):
            return set()
        lvl = _arg(node, 4, "level")
        level = (lvl.value if isinstance(lvl, ast.Constant)
                 and isinstance(lvl.value, int) and not isinstance(lvl.value, bool)
                 else 0)
        # A relative __import__ takes its package from the GLOBALS it is handed, not
        # from where the call is written -- verified against the interpreter:
        # `__import__("<mod>", {"__package__": "<other>"}, None, (), 1)` loads
        # <other>.<mod> from anywhere. So a dict literal saying so wins over the
        # caller's own location (Codex [P2], fourth round on PR #58).
        # An OPAQUE globals expression still falls back to the caller's location, and
        # deliberately: in real code that argument is the caller's own globals, and
        # refusing to resolve it would trade an exotic misattribution for an ordinary
        # miss -- the direction that lets a breaking change through.
        if not mod and not level:
            return set()  # `__import__("")` at level 0 is a ValueError, not an import
        base = list(here) if level else []
        named_pkg = _literal_str(_dict_value(_arg(node, 1, "globals"), "__package__"))
        if level and named_pkg is not None:
            base = named_pkg.split(".") if named_pkg else []
    else:
        if not mod:
            return set()  # import_module has no empty-name form
        if not mod.startswith("."):
            return _with_fromlist(node, [mod], fname)
        # import_module resolves a relative name against `package`, and REQUIRES one.
        pkg_arg = _arg(node, 1, "package")
        pkg = _literal_str(pkg_arg)
        if pkg:
            base = pkg.split(".")
        elif isinstance(pkg_arg, ast.Name) and pkg_arg.id == "__package__":
            # The canonical spelling, and the only non-literal package worth resolving:
            # at module scope `__package__` IS the importer's own package.
            base = list(here)
        else:
            return set()
        level = len(mod) - len(mod.lstrip("."))
        mod = mod.lstrip(".")

    climb = max(level - 1, 0)
    if climb > len(base):
        return set()  # climbs out of the repo: names nothing in it
    parts = base[:len(base) - climb] + ([mod] if mod else [])
    return _with_fromlist(node, parts, fname)


def imported_names(text: str, rel: str) -> set[str] | None:
    """The dotted module names a Python source imports, via AST — or None when it will
    not parse, in which case the caller falls back to literal matching alone.

    `rel` is the importing file's own path, needed to resolve RELATIVE imports:
      import a.b.c        -> {"a.b.c"}
      from a.b import c   -> {"a.b", "a.b.c"}
      from . import foo   -> {"<pkg>.foo"}
      from .foo import X  -> {"<pkg>.foo"}
    Parenthesised and backslash-continued imports parse natively here — those are the
    forms a line-oriented regex kept missing.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    ip = Path(rel)
    pkg_parts = list(ip.parent.parts)
    if pkg_parts == ["."]:
        pkg_parts = []
    if ip.suffix == ".pyi":
        # The same normalization the target side does -- a relative import inside a
        # stub package resolves under the name the package PROVIDES stubs for.
        pkg_parts = _strip_stubs(pkg_parts)
    modules_ns, loader_kinds = _loader_bindings(tree)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # A module named by a literal string at a loader call. For a name too short
            # for word_token's floor this is the ONLY place it appears, so without it a
            # real plugin loader is invisible while the same call is found for any
            # longer name.
            names |= _dynamic_module(node, pkg_parts, modules_ns, loader_kinds)
            continue
        if isinstance(node, ast.Import):
            for a in node.names:
                names.add(a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # `from . import x` is level 1 in the file's own package; each extra
                # dot climbs one parent.
                climb = node.level - 1
                base = pkg_parts[:len(pkg_parts) - climb] if climb <= len(pkg_parts) else []
                prefix = base + ([node.module] if node.module else [])
                if prefix:
                    names.add(".".join(prefix))
                for a in node.names:
                    if prefix:
                        names.add(".".join(prefix + [a.name]))
            elif node.module:
                names.add(node.module)
                for a in node.names:
                    names.add(node.module + "." + a.name)
    return names


def resolve_js_specifier(importer_rel: str, spec: str, known: set[str]) -> set[str]:
    """Repo-relative paths a relative JS/TS specifier could name.

    Resolution is against the IMPORTER's directory, which is the whole point: a bare
    basename token cannot tell `db/<name>.ts` from `ingest/<name>.ts` when each is
    imported from its own directory as the identical `'./<name>.js'`. Only the
    importer's location separates them. Returns candidates rather than picking one --
    the caller only asks whether a target is among them, so guessing Node's precedence
    order wrong cannot produce a wrong answer, only a slightly wider one.
    """
    joined = os.path.normpath(os.path.join(os.path.dirname(importer_rel), spec))
    if joined == "." or joined == ".." or joined.startswith(".." + os.sep):
        # Climbs out of the repo. Empty is the correct answer, not a swallowed
        # failure: every target comes from this repo's own diff, so it is always a
        # repo-relative path inside the root, and a specifier resolving outside can
        # never name one. The caller unions this into a set and asks `t in resolved`,
        # so it never depends on the result being non-empty.
        return set()
    out = {joined}
    stem, ext = os.path.splitext(joined)
    if ext in JS_SPEC_TO_SOURCE:
        # The NodeNext case: './<dir>/<name>.js' written for <dir>/<name>.ts.
        out.update(stem + e for e in JS_SPEC_TO_SOURCE[ext])
    elif joined not in known:
        # The specifier does not name a file that exists, so it can only be an
        # implied-extension or directory form -- expand it.
        #
        # This asks the TREE rather than guessing from the extension, and that is the
        # point. Three rounds of review each found a different extension the guess got
        # wrong in a different direction: './<name>.json' must not invent
        # '<name>.json.ts'; './<name>.test' must still reach <name>.test.ts; and
        # './<name>.css' must still reach a bundler's <name>.css.ts. No list of
        # extensions can settle those, because the extension is not what distinguishes
        # them -- whether the named file exists is. An existing file terminates the
        # specifier; a missing one means the extension was implied.
        out.update(joined + e for e in JS_SOURCE_EXT)
        out.update(f"{joined}/index{e}" for e in JS_SOURCE_EXT)
    return out


def find_dependents(root: Path, targets: list[str],
                    rename_pairs: list[tuple[str, str]] | None = None
                    ) -> tuple[dict, int, list[str]]:
    """Returns (dependents_by_target, files_scanned, scan_errors)."""
    files = tracked_files(root)
    basename_counts = Counter(f.name for f in files)
    target_set = set(targets)
    # A DELETED target is absent from ls-files, so its basename would read count 0
    # and the bare-basename token would silently never fire. Counting the target
    # itself restores the right reading: a previously-unique deleted basename is 1
    # (still matches); one shadowed by a surviving same-name file is 2 (ambiguous,
    # dropped — the mention may well mean the survivor).
    tracked_rels = {str(f.relative_to(root)) for f in files}
    # ...but a RENAME's two halves are ONE file, so the pair must contribute ONE count.
    # A directory-only move (old/x.sh -> new/x.sh) otherwise counts "x.sh" twice — once
    # tracked at the destination, once for the untracked source — which reads as
    # ambiguous and drops the bare-basename token for BOTH halves, so a caller saying
    # only "x.sh" vanishes from the blast radius entirely. Measured on a fixture: the
    # dependent set went from {new/x.sh: [uses.md]} to {} (Codex [P2], 2026-08-29).
    # Deliberately narrow: only a real rename pair whose basename did NOT change and
    # whose destination is tracked. An unrelated delete-plus-modify that happens to
    # share a basename is still counted twice, which is the ambiguity it really is.
    same_identity = {src for src, dst in (rename_pairs or [])
                     if Path(src).name == Path(dst).name and dst in tracked_rels}
    for t in target_set - tracked_rels:
        if t in same_identity:
            continue
        basename_counts[Path(t).name] += 1
    # Tracked files plus the targets: a DELETED target is absent from ls-files, and a
    # specifier naming it should still terminate rather than expand into inventions.
    known_paths = tracked_rels | target_set
    token_map = {t: literal_tokens(t, basename_counts) for t in targets}
    form_map = {t: module_dotted_forms(t) for t in targets}
    # Bare module names are matched on word boundaries, compiled once per target rather
    # than per (target, file) pair.
    word_map = {}
    for t in targets:
        w = word_token(t)
        if w:
            word_map[t] = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(w) + r"(?![A-Za-z0-9_])")
    # Importing ANY submodule of a package runs that package's __init__.py -- `import
    # pkg.sub` and `from pkg.sub import X` both execute it -- so an importer whose name
    # merely STARTS with the package form is a real dependent of the initializer. Module
    # targets stay exact; only package targets match by prefix.
    pkg_map = {t: Path(t).stem == "__init__" and Path(t).suffix in PY_FAMILY_SUFFIX
               for t in targets}
    deps: dict[str, set] = {t: set() for t in targets}
    scanned, errors = 0, []

    def _py_match(forms: set[str], is_pkg: bool, imports: set[str]) -> bool:
        if forms & imports:
            return True
        if is_pkg:
            return any(n == fm or n.startswith(fm + ".") for fm in forms for n in imports)
        return False

    for f in files:
        rel = str(f.relative_to(root))
        if rel in target_set:
            continue  # a file is not its own dependent
        text = readable_text(f)
        if text is None:
            continue
        if text is SKIPPED:
            errors.append(rel)  # inspectable but unreadable — main() fails closed
            continue
        scanned += 1
        # Resolved once per FILE, not once per target: the specifiers a file contains
        # do not depend on which target is being asked about.
        resolved: set[str] = set()
        if f.suffix.lower() in JS_FAMILY_SUFFIX:
            for _quote, spec in REL_SPEC_RE.findall(text):
                if INTERPOLATION in spec:
                    continue
                resolved |= resolve_js_specifier(rel, spec, known_paths)
        # AST imports for a .py dependent, resolved once per FILE like the JS
        # specifiers above. None when the file will not parse, in which case the
        # literal check below is the only signal -- the conservative fallback.
        imports = (imported_names(text, rel)
                   if f.suffix in PY_FAMILY_SUFFIX else None)
        for t, tokens in token_map.items():
            wrx = word_map.get(t)
            named = (t in resolved or any(tok in text for tok in tokens)
                     or (wrx is not None and wrx.search(text) is not None))
            imported = imports is not None and _py_match(form_map[t], pkg_map[t], imports)
            if named or imported:
                deps[t].add(rel)
    return deps, scanned, errors


def positive_control(root: Path) -> tuple[bool, str]:
    """Prove the scan can actually find things before trusting an empty result.

    Picks a string this tool has independently confirmed is present — the repo's own
    .gitignore content — and searches for it the same way the real sweep does. If the
    control fails, the sweep is broken, not the repo.
    """
    gi = root / ".gitignore"
    # is_symlink BEFORE is_file, because is_file() FOLLOWS the link. The control reads
    # its needle out of this file and then prints that needle into its own message, and
    # the gate job runs with BROKER_TOKEN and a forge token in its environment -- so a
    # .gitignore symlinked at a credential-bearing path (.git/config, /proc/self/environ,
    # an .env) puts the target's longest line straight into the CI log. Demonstrated,
    # not theorised: a fixture symlinking .gitignore to a file containing
    # BROKER_TOKEN=... printed that line verbatim as "control '<token>' found in 2
    # file(s)" and exited 0.
    #
    # Reachable here through owner ACCIDENT rather than a malicious PR -- this is a
    # single-owner repo and every consumer runs the gate on `pull_request`, not
    # `pull_request_target` -- but the cost of the accident is a secret in a log, which
    # is not a class this project trades against convenience. A symlinked control source
    # is UNKNOWN, not usable. Ported from the claude-memory deployed copy alongside the
    # readable_others hardening it shipped with.
    try:
        if gi.is_symlink() or not gi.is_file():
            return False, "no regular-file .gitignore to use as a control"
    except OSError:
        return False, "cannot stat .gitignore control source"
    # Prefer the LONGEST entry: a short generic token like "data" would still match in a
    # sweep that was half-broken, which is exactly what a control must not do.
    entries = [ln.strip().rstrip("/") for ln in gi.read_text().splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    needle = max(entries, key=len) if entries else None
    if needle and len(needle) < 4:
        needle = None
    if not needle:
        return False, ".gitignore has no usable control token"

    # TWO independent claims, both required, because the token search alone is
    # SELF-SATISFYING: the needle comes FROM .gitignore, so it matches .gitignore itself
    # even when every other tracked file has become invisible to the walk. A sweep that
    # could read nothing else still reported "control found in 1 file(s)", passed, and
    # went on to report a clean empty blast radius — the control certifying only its own
    # source, which is the precise failure this whole function exists to prevent, sitting
    # inside the thing meant to prevent it. Measured on a fixture whose only other
    # tracked file is a skipped binary: exit 0, "found in 1 file(s)".
    #
    # So also require that the walk actually READ something else: visibility of the tree,
    # proven independently of the token's own source. Ported from the claude-memory
    # deployed copy, which fixed this after a Codex review on 2026-08-22 and has been
    # carrying it alone since; its pre-push tests are what caught the source of truth
    # still shipping the weak version.
    #
    # isinstance, not truthiness: an EMPTY tracked file is readable and proves visibility
    # just as well, but "" is falsy and would not have counted.
    hits = 0
    readable_others = 0
    for f in tracked_files(root):
        text = readable_text(f)
        if not isinstance(text, str):
            continue
        if f != gi:
            readable_others += 1
        if needle in text:
            hits += 1
    if hits == 0:
        return False, f"control token {needle!r} found in 0 files — the sweep cannot see the tree"
    if readable_others == 0:
        return False, ("control token found only in its own source file and no other "
                       "tracked file was readable — the tree is not visible to the sweep")
    return True, f"control {needle!r} found in {hits} file(s); {readable_others} other file(s) readable"


def changed_files(root: Path, base: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Every path the change touches, BOTH halves of a rename included.

    Returns (paths, rename_pairs). The pairs are returned rather than discarded because
    the two halves of a rename are ONE file, and find_dependents needs to know that to
    count its basename once — see the same-identity note there.

    NOT --name-only: for a detected rename it prints only the destination, so the
    dependent sweep never looks for callers of the OLD path and a rename that breaks
    every importer resolves to zero dependents (mcp-techkb PR #13's R100 of
    .github/workflows/secret-scan.yml, Codex [P1] 2026-08-29). The old path is exactly
    the one whose dependents are now broken, so dropping it inverts the tool's purpose.

    -z because the fields are NUL-delimited: paths may contain spaces or newlines, and
    --name-status without -z would also C-quote non-ASCII names into paths that match
    nothing on disk.

    -M -C -l0 because detection must not depend on the consuming repo's git config. Under
    diff.renames=false a move emits separate D/A records, rename_pairs comes back empty,
    and the same-identity fix below silently stops working — a directory-only move then
    counts its basename twice and drops the token, losing exactly the dependents this
    function exists to find (Codex [P2], 2026-08-29). Each flag closes a different way
    the config can turn detection off, all three measured on git 2.50.1:

      -M   forces rename detection under diff.renames=false, which otherwise emits D/A.
      -C   because -M ALONE overrides diff.renames=copies and turns a detected copy back
           into a plain addition, quietly disabling the C handling in review-pr.sh.
      -l0  because diff.renameLimit caps the exhaustive pass: at renameLimit=1 a fixture
           of four moved-and-edited files dropped from 4 R records to 0 even WITH -M -C.
           -l0 is unlimited and restored all four.

    -l0 covers INEXACT renames specifically — a file moved AND edited. An exact rename is
    paired in a cheap pre-pass that no limit touches, so the R100 case that motivated all
    of this was never at risk; "moved it and tweaked it" is, and is the more common shape.
    git warns on stderr when it skips the pass, but this call captures stderr and drops
    it, so the degradation would have been silent.
    """
    out = subprocess.run(["git", "-C", str(root), "diff", "--name-status", "-z",
                          "-M", "-C", "-l0", f"{base}...HEAD"],
                         capture_output=True, text=True, check=True)
    fields = out.stdout.split("\0")
    paths: list[str] = []
    renames: list[tuple[str, str]] = []
    i = 0
    while i < len(fields):
        status = fields[i]
        if not status.strip():
            i += 1
            continue
        # R/C carry <status>\0<source>\0<destination>; everything else one path.
        want = 2 if status[0] in ("R", "C") else 1
        got = [p for p in fields[i + 1:i + 1 + want] if p.strip()]
        if len(got) < want:
            raise SystemExit(
                f"FATAL: git diff --name-status ended mid-record after {status!r} — "
                "refusing to scan a truncated file list"
            )
        if status[0] == "R":
            renames.append((got[0], got[1]))
            paths.extend(got)
        elif status[0] == "C":
            # A COPY does not change its source: the file is still there, still saying
            # what it said. Only the destination is new, so only the destination is part
            # of this change. Treating the source as changed would scan a file nothing
            # happened to and, in review-pr.sh, submit an empty diff the model would
            # still count as examined (Codex [P2], 2026-08-29).
            paths.append(got[1])
        else:
            paths.extend(got)
        i += 1 + want
    # dict.fromkeys dedupes while holding git's order (a path can appear twice when a
    # rename's destination is itself the source of another entry).
    return list(dict.fromkeys(paths)), renames


def main() -> int:
    args = sys.argv[1:]
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    root = repo_root()

    if args and args[0] == "--changed-from":
        if len(args) < 2:
            sys.stderr.write("--changed-from needs a base ref\n")
            return 2
        targets, rename_pairs = changed_files(root, args[1])
        if not targets:
            sys.stderr.write(f"FATAL: no files changed vs {args[1]} — nothing to review\n")
            return 1
    else:
        targets, rename_pairs = args, []
    if not targets:
        sys.stderr.write(__doc__.split("Usage:")[1])
        return 2

    ok, control_msg = positive_control(root)
    if not ok:
        sys.stderr.write(f"FATAL: positive control FAILED — {control_msg}\n"
                         f"       Reporting UNKNOWN, not 'no dependents'. A dependency sweep\n"
                         f"       that cannot find a string it was told is there is broken.\n")
        return 1

    deps, scanned, scan_errors = find_dependents(root, targets, rename_pairs)
    # The third return value used to be discarded into `_`: files the sweep could not
    # read looked exactly like files with no dependents. They are now counted, named on
    # the console, and carried in the JSON as `unreadable`, so a partial sweep is
    # legible instead of silent.
    #
    # REPORTED, NOT FATAL — deliberately, and this is the one place this port departs
    # from the claude-memory copy it came from. That copy exits 1 here, on the correct
    # principle that an incomplete radius is UNKNOWN. It gets away with it because it is
    # deployed in exactly one repo, which happens to track no oversized or undecodable
    # file. Measured across the six repos this kit actually deploys into, that policy
    # hard-fails TWO of them on their current main: claudeclaw
    # (benchmark/longmemeval/data/longmemeval_oracle_slim.json, over the 512,000-byte
    # cap) and geekspace (build/icon.icns, a binary suffix not in SKIP_SUFFIX). A gate
    # that fails every run in a repo is one that gets routed around, which costs more
    # than the partial scan it was refusing. Escalating this to fatal is a real
    # improvement, but it needs those two files triaged first, not a flag day.
    if scan_errors:
        shown = ", ".join(sorted(scan_errors)[:5])
        more = "" if len(scan_errors) <= 5 else f" (+{len(scan_errors) - 5} more)"
        sys.stderr.write(
            f"WARNING: {len(scan_errors)} tracked file(s) could not be read as text and "
            f"were never searched: {shown}{more}\n"
            f"         Any of them may reference a changed target, so this blast radius "
            f"is INCOMPLETE, not proven empty.\n")
    # The control proves the tree is READABLE; this proves the sweep actually WALKED it.
    # Those are different claims, and only checking the first leaves a path where the
    # control passes while zero files were examined. Prompted by the gate reviewing its
    # own diff — its stated reasoning was wrong, but the asymmetry it pointed at was real.
    if scanned == 0:
        sys.stderr.write("FATAL: control passed but the sweep scanned 0 files — UNKNOWN, "
                         "not 'no dependents'.\n")
        return 1
    total = sorted({d for s in deps.values() for d in s})

    if as_json:
        print(json.dumps({
            "targets": targets, "files_scanned": scanned,
            "unreadable": sorted(scan_errors),
            "control": control_msg,
            "dependents": {t: sorted(v) for t, v in deps.items()},
            "blast_radius": total,
        }, indent=2))
    else:
        print(f"control: {control_msg}")
        for t in targets:
            d = sorted(deps[t])
            print(f"\n{t} — {len(d)} dependent(s)")
            for x in d:
                print(f"    {x}")
        print(f"\n── scanned {scanned} text file(s); blast radius {len(total)} unique file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
