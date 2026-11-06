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
  bin/blast-radius.py --json --changed-from BASE --declare-generated
                                               # as review-pr.sh calls it: may report a
                                               # compiled viewer as a declared exclusion
  bin/blast-radius.py --jsonl-digest BASE HEAD DECL < path/status pairs (NUL-separated)
                                               # review-pr.sh 1c: declared ledgers' digests
  bin/blast-radius.py --not-applicable VERDICT N < standards (a JSON array)
                                               # review-pr.sh 5: judge and render a verdict's
                                               # per-standard not-applicable reasons
  bin/blast-radius.py --unmatched VERDICT REQUEST
                                               # review-pr.sh 5: re-judge and render findings
                                               # that name no supplied file (CLAUDE.md 4.8)
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
from decimal import Decimal, InvalidOperation
from pathlib import Path

# Never read these as text, and never call them dependents.
SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".docx", ".xlsx",
               ".woff", ".woff2", ".ico", ".zst", ".db", ".sqlite"}
MAX_FILE_BYTES = 512_000

# The ONE generated artifact the sweep may set aside rather than call unreadable: the
# compiled diagram viewer /doco-refresh commits beside its JSON source, as
# <name>.architecture.html and <name>.architecture.json under the directory below. The
# viewer is ~700 KB in every repo that tracks one (33 on the forge, 710-724 KB, measured
# 2026-10-10), so it was over MAX_FILE_BYTES on every run and the INCOMPLETE warning
# became permanent in ten consumers -- a warning that never changes hides the unreadable
# file that matters. Same shape and same reasoning as review-pr.sh section 1b.
#
# Two conditions, BOTH required, and the second is the load-bearing one:
#   1. the path has this prefix and this suffix AND the sweep could not read it (a viewer
#      it CAN read is searched like any other file);
#   2. the sibling source was read and searched in this same run, or is itself a readable
#      changed target -- in which case it is not searched (no changed file is) but is
#      reviewed directly. An absent, oversized or undecodable source stands in for nothing.
# Without (2) this is a blanket exemption for a path shape. Excluded files are DECLARED --
# on the console and in the JSON -- never dropped: an undeclared exclusion reads as
# "searched everything".
#
# OPT-IN, per call (--declare-generated). The two kit scripts are redeployed as a pair but
# do drift apart: a consumer can hold this resolver beside a review-pr.sh that predates
# `generated_excluded`. That gate reads only `unreadable`, so a viewer moved out of it
# would vanish from the comment while the comment claimed a complete sweep -- declared
# nowhere a reader looks. So the caller must say it can disclose an exclusion; without the
# flag every viewer is unreadable, exactly as before. An OLDER resolver ignores the flag
# (it reads nothing after the base ref), so the new gate is safe beside it too.
#
# Path characters are ALLOWLISTED, here and identically in review-pr.sh, because excluded
# paths are printed into the comment forge-pr parses. A tracked path may hold a newline,
# a backtick or a Unicode line separator; such a viewer is never excluded and stays
# merely unreadable, which is advisory, rather than stopping the gate on every PR.
#
# THREAT MODEL: private single-owner repos; the adversary is an owner ACCIDENT, not a
# contributor hiding a file from review. A hand-written file placed at this path shape
# beside a small JSON would leave the sweep, declared in every comment. Accepted.
#
# The source stands in because the viewer is a constant runtime plus that JSON. Measured
# with this file's own token rules on four consumers: every target the viewer matched,
# the source matched too (0 viewer-only matches). Re-measured per consumer at redeploy.
GENERATED_VIEWER_DIR = "docs/diagrams/"
GENERATED_VIEWER_SUFFIX = ".architecture.html"
GENERATED_SOURCE_SUFFIX = ".architecture.json"
GENERATED_PATH_RE = re.compile(r"[A-Za-z0-9._/-]+")

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
                    rename_pairs: list[tuple[str, str]] | None = None,
                    declare_generated: bool = False
                    ) -> tuple[dict, int, list[str], list[tuple[str, str]]]:
    """Returns (dependents_by_target, files_scanned, scan_errors, generated_excluded).

    generated_excluded is (viewer, source) pairs: compiled viewers the sweep could not
    read whose source stands in for them. Always empty unless declare_generated is set.
    See GENERATED_VIEWER_DIR."""
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
    # Paths that were actually read and searched, and unreadable viewers waiting on them.
    # Pairing is decided AFTER the loop so it cannot depend on the order git lists files.
    searched: set[str] = set()
    pending_viewers: list[str] = []

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
            if (declare_generated
                    and rel.startswith(GENERATED_VIEWER_DIR)
                    and rel.endswith(GENERATED_VIEWER_SUFFIX)
                    and GENERATED_PATH_RE.fullmatch(rel)):
                pending_viewers.append(rel)  # unreadable unless its source was searched
            else:
                errors.append(rel)  # inspectable but unreadable — main() fails closed
            continue
        scanned += 1
        searched.add(rel)
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
    excluded: list[tuple[str, str]] = []
    for rel in pending_viewers:
        source = rel[:-len(GENERATED_VIEWER_SUFFIX)] + GENERATED_SOURCE_SUFFIX
        # A source that is itself a changed target was skipped by the loop above, as
        # every changed file is, so it was NOT searched and is not in `searched`. It
        # still pairs, when tracked and readable, because it is reviewed directly: the
        # model reads the changed files themselves. A DELETED source is in neither set
        # and pairs with nothing.
        target_source = (source in target_set and source in tracked_rels
                         and isinstance(readable_text(root / source), str))
        if source in searched or target_source:
            excluded.append((rel, source))
        else:
            errors.append(rel)
    return deps, scanned, errors, excluded


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


# ---- JSONL digest: a second job, hosted here only for the kit's size limit ----------
# review-pr.sh section 1c sends a DECLARED JSONL table as this digest in place of its raw
# diff (the 2026-10-25 change folder under docs/changes/). This side reads the declaration,
# applies every condition, and reports each path it did NOT digest and why; review-pr.sh
# only sends and discloses what comes back. It lives in this file because
# review-pr.sh must stay under the per-file cap that reviews its own install PR, and every
# consumer's workflow already copies exactly these two scripts. It reads committed blobs
# only, never the working tree, and shares nothing with the resolver above. It must never
# name a real path, the declaration's included (review-pr.sh passes it): see the note on
# example paths in the module docstring.
#
# The declaration is read from BASE, never the PR, and a PR that changes it digests
# nothing, so no PR can declare its own exemption. One "<path><TAB><key>[,<key>...]" per
# line; blank and # lines are ignored; one malformed line disables every digest.
#
# Edited and removed rows go IN FULL as -/+ lines, because an in-place edit is where the
# table's accidents are. Appended rows go only as counts and per-field value tallies.
# Rows are classified by RAW LINE TEXT per key, never by parsed values. Anything that is
# not a keyed JSONL table raises LedgerError, and the caller sends the raw diff instead.
LEDGER_MARKER = "LEDGER DIGEST (review-pr.sh): rows summarized by key, not a raw diff"
LEDGER_ENUM_MAX = 12   # at most this many distinct values: each is listed with its count
LEDGER_SHOWN_MAX = 80  # characters of one listed value before it is shortened
LEDGER_FIELD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")  # a field name, and a declared key


class LedgerError(Exception):
    """A copy that cannot be digested: not a keyed JSONL table, or not readable."""


def _no_constant(name: str) -> None:
    raise ValueError(f"non-JSON constant {name}")


def ledger_rows(text: str, keys: list[str], side: str) -> dict[str, tuple[str, dict]]:
    """{key: (raw line, parsed object)} for one copy, or LedgerError naming the line."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    rows = {}
    for n, raw in enumerate(lines, 1):
        if raw == "":
            raise LedgerError(f"{side}: line {n} is empty")
        try:
            obj = json.loads(raw, parse_constant=_no_constant, parse_float=Decimal)
        except ValueError:
            raise LedgerError(f"{side}: line {n} is not JSON") from None
        # Valid JSON a Decimal cannot hold (1e9999999999999999999) is not a ValueError.
        except InvalidOperation:
            raise LedgerError(f"{side}: line {n} has a number out of range") from None
        if not isinstance(obj, dict):
            raise LedgerError(f"{side}: line {n} is not a JSON object")
        # Field names are printed into the digest as they are, so only plain ones: a newline
        # in one could forge digest lines (review of 2026-10-26).
        bad = [f for f in obj if not LEDGER_FIELD_RE.fullmatch(f)]
        if bad:
            raise LedgerError(f"{side}: line {n} has a field name that is not a plain "
                              f"identifier: {json.dumps(bad[0])}")
        parts = []
        for k in keys:
            v = obj.get(k)
            # bool is an int in Python, so a true/false key is not a key. Nor is a float: 1 and
            # 1.0 would get different identities, turning an edit into removed plus appended.
            if isinstance(v, bool) or not isinstance(v, (str, int)):
                raise LedgerError(f"{side}: line {n} has no string or integer in key field {k}")
            parts.append(json.dumps(v))
        key = "\x01".join(parts)
        if key in rows:
            raise LedgerError(f"{side}: duplicate key {','.join(parts)}")
        rows[key] = (raw, obj)
    return rows


def _canonical_json(v: object) -> str:
    # A decimal is its text: as a float, 9007199254740992.0 and 9007199254740993.0 are one
    # value, so an edit between them would read as no change (Codex review of PR #187).
    if isinstance(v, Decimal):
        return str(v)
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _canonical_json(v[k])
                              for k in sorted(v)) + "}"
    if isinstance(v, list):
        return "[" + ",".join(_canonical_json(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)


def _shortened(s: str) -> str:
    return s if len(s) <= LEDGER_SHOWN_MAX else f"{s[:LEDGER_SHOWN_MAX]}... ({len(s)} chars)"


def ledger_digest(path: str, keys: list[str], base_text: str,
                  head_text: str) -> tuple[str, tuple[int, int, int]]:
    base = ledger_rows(base_text, keys, "merge base")
    head = ledger_rows(head_text, keys, "reviewed commit")
    added = [head[k][1] for k in sorted(head) if k not in base]
    removed_lines = [base[k][0] for k in sorted(base) if k not in head]
    modified_pairs = [(base[k], head[k]) for k in sorted(head)
                      if k in base and base[k][0] != head[k][0]]
    out = [LEDGER_MARKER, f"path: {path}", f"key: {','.join(keys)}",
           f"rows: base {len(base)}, head {len(head)}",
           f"appended {len(added)} (summarized below, row text NOT shown), "
           f"modified {len(modified_pairs)}, removed {len(removed_lines)} (shown in full)"]
    # Reordered rows or a lost final newline change no row, and would otherwise read as an
    # empty change (review of 2026-10-26).
    if base_text != head_text and not (added or removed_lines or modified_pairs):
        out.append("no row changed, but the file did (row order, or the final newline)")
    out += ["", f"modified rows ({len(modified_pairs)}):"]
    for (braw, bo), (hraw, ho) in modified_pairs:
        changed = [f for f in sorted(set(bo) | set(ho))
                   if f not in bo or f not in ho or _canonical_json(bo[f]) != _canonical_json(ho[f])]
        out += ["-" + braw, "+" + hraw, "  changed fields: "
                + (", ".join(changed) or "none (the line text changed, no value did)")]
    out += ["", f"removed rows ({len(removed_lines)}):"] + ["-" + r for r in removed_lines]
    out += ["", f"appended rows ({len(added)}), per field:"]
    added_fields = sorted({f for o in added for f in o})
    for f in added_fields:
        # A missing field is not a null: a reader that subscripts it fails on one.
        absent = sum(f not in o for o in added)
        nulls = sum(f in o and o[f] is None for o in added)
        tally = Counter(_canonical_json(o[f]) for o in added if o.get(f) is not None)
        line = f"  {f}: " + (f"{absent} absent, " if absent else "") + f"{nulls} null"
        if not tally:
            out.append(line)
        elif len(tally) <= LEDGER_ENUM_MAX:
            shown = [f"{_shortened(s)} x{c}"
                     for s, c in sorted(tally.items(), key=lambda t: (-t[1], t[0]))]
            out.append(f"{line}; {', '.join(shown)}")
        else:
            out.append(f"{line}, {len(tally)} distinct")
    if added:
        base_fields = {f for _, o in base.values() for f in o}
        only_added = sorted(set(added_fields) - base_fields)
        only_base = sorted(base_fields - set(added_fields))
        out.append(f"fields only in appended rows: {', '.join(only_added) or 'none'}")
        out.append(f"fields only in base rows: {', '.join(only_base) or 'none'}")
    counts = (len(added), len(modified_pairs), len(removed_lines))
    return "\n".join(out) + "\n", counts


def _blob(root: Path, ref: str, path: str) -> bytes | None:
    out = subprocess.run(["git", "-C", str(root), "show", f"{ref}:{path}"], capture_output=True)
    return out.stdout if out.returncode == 0 else None


def _mode(root: Path, ref: str, path: str) -> str | None:
    out = subprocess.run(["git", "-C", str(root), "ls-tree", ref, "--", path],
                         capture_output=True, text=True)
    return out.stdout.split(" ", 1)[0] if out.returncode == 0 and out.stdout else None


def ledger_plan(root: Path, base: str, head: str, decl: str,
                changed: list[tuple[str, str]]) -> dict[str, list]:
    """{skipped, digests} for review-pr.sh. `changed` is [(path, status)] as it sends them."""
    skipped, digests, declared = [], [], {}
    jsonl_count = sum(p.endswith(".jsonl") for p, _ in changed)
    raw = _blob(root, base, decl)
    if raw is None:
        if jsonl_count:
            skipped.append(f"no {decl} on {base}; {jsonl_count} .jsonl file(s) reviewed as raw diffs")
        return {"skipped": skipped, "digests": digests}
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        bad = ("not exactly one TAB" if len(cols) != 2
               else "path does not end .jsonl" if not cols[0].endswith(".jsonl")
               else "keys are not field names"
               if not all(LEDGER_FIELD_RE.fullmatch(k) for k in cols[1].split(","))
               else "path declared twice" if cols[0] in declared else "")
        if bad:
            skipped.append(f"{decl} on {base} is malformed ({bad}: {line!r}); nothing is digested")
            return {"skipped": skipped, "digests": digests}
        declared[cols[0]] = cols[1].split(",")
    if any(p == decl for p, _ in changed):
        skipped.append(f"this PR changes {decl} itself; nothing is digested")
        return {"skipped": skipped, "digests": digests}
    # Said, never passed over: a typo, a "./" prefix or a byte-order mark in the declaration
    # would otherwise send a table as a raw diff with nothing pointing at why.
    for path, _ in changed:
        if path.endswith(".jsonl") and path not in declared:
            skipped.append(f"{path} is not declared in {decl}; raw diff")
    mb = subprocess.run(["git", "-C", str(root), "merge-base", base, head],
                        capture_output=True, text=True)
    if mb.returncode != 0:
        skipped.append(f"no merge base with {base}; nothing is digested")
        return {"skipped": skipped, "digests": digests}
    for path, status in changed:
        if path not in declared:
            continue
        if status != "modified":
            skipped.append(f"{path} NOT digested (it is {status}, not modified); raw diff")
            continue
        # A digest compares contents only, so a mode change (identical blobs) would read as
        # no change at all and never reach the model (Codex review of 0fd0fb9).
        if _mode(root, mb.stdout.strip(), path) != _mode(root, head, path):
            skipped.append(f"{path} NOT digested (its file mode changed); raw diff")
            continue
        old, new = _blob(root, mb.stdout.strip(), path), _blob(root, head, path)
        try:
            if old is None or new is None:
                raise LedgerError("a copy could not be read")
            text, counts = ledger_digest(path, declared[path],
                                         old.decode("utf-8"), new.decode("utf-8"))
        except UnicodeDecodeError:
            skipped.append(f"{path} NOT digested (a copy is not UTF-8); raw diff")
            continue
        except RecursionError:
            skipped.append(f"{path} NOT digested (a value is nested too deeply to read); raw diff")
            continue
        except LedgerError as e:
            skipped.append(f"{path} NOT digested ({e}); raw diff")
            continue
        digests.append({"path": path, "text": text, "appended": counts[0],
                        "modified": counts[1], "removed": counts[2]})
    return {"skipped": skipped, "digests": digests}


def ledger_digest_cli(args: list[str]) -> int:
    """--jsonl-digest BASE HEAD DECL, with NUL-separated path/status pairs on stdin:
    the plan as JSON on stdout. Non-zero only when this side itself broke."""
    if len(args) != 3:
        sys.stderr.write("--jsonl-digest needs BASE HEAD DECL, path/status pairs on stdin\n")
        return 2
    fields = sys.stdin.buffer.read().decode("utf-8", "surrogateescape").split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 2:
        sys.stderr.write("--jsonl-digest: stdin is not path/status pairs\n")
        return 2
    changed = list(zip(fields[0::2], fields[1::2]))
    print(json.dumps(ledger_plan(repo_root(), args[0], args[1], args[2], changed)))
    return 0


# review-pr.sh section 5's fourth zero-standards exception (CLAUDE.md section 4.7; geekspace
# forge PR #84, TOML and shell reviewed against rules about Electron and Convex). It lives
# here, not in review-pr.sh, for the reason the digest above does: review-pr.sh must stay
# under the per-file cap that reviews its own install PR (selftest case 19).
# The bounds must match review-broker.py's NA_REASON_MIN_CHARS/MAX_CHARS by inspection.
NA_REASON_MIN_CHARS = 12
NA_REASON_MAX_CHARS = 300
# How many standards are NAMED in the comment, as review-pr.sh's STD_LABEL_CAP; the rest
# are counted. Each label keeps this many characters of the standard's text.
NA_LABEL_CAP = 200
NA_LABEL_CHARS = 100
# Every control character and Unicode line separator becomes a space, so a label or reason
# stays one blockquote line and cannot forge a line forge-pr parses.
_NA_BREAKS = {c: " " for c in [*range(32), 127, 133, 0x2028, 0x2029]}


def _na_text(value: object) -> str:
    return str(value).translate(_NA_BREAKS)


def not_applicable_problem(rows: object, n: int) -> str | None:
    """Why `rows` does NOT say, for every one of `n` standards, that it does not apply and
    why; None when it does. The broker applies the same rules (_not_applicable_problem); this
    copy is the client's, so a broker field is never trusted. Each standard 1..n exactly
    once, `applies` exactly false, a reason NA_REASON_MIN..MAX characters once trimmed, and
    no reason shared by two standards once case and whitespace are folded: one sentence
    pasted onto every rule is not a judgement about any of them."""
    if not isinstance(rows, list) or not rows:
        return "the verdict carries no standards_not_applicable list"
    if n <= 0 or len(rows) != n:
        return f"the list answers {len(rows)} standard(s) of {n}"
    seen: set = set()
    reasons: set = set()
    for row in rows:
        if not isinstance(row, dict):
            return "an entry is not an object"
        num, reason = row.get("standard"), row.get("reason")
        if isinstance(num, bool) or not isinstance(num, int) or not 1 <= num <= n or num in seen:
            return f"standard number {num!r} is out of range or repeated"
        seen.add(num)
        if row.get("applies") is not False:
            return f"standard {num} is not marked as not applicable"
        if not isinstance(reason, str):
            return f"standard {num}: the reason is not text"
        text = reason.strip()
        if not NA_REASON_MIN_CHARS <= len(text) <= NA_REASON_MAX_CHARS:
            return (f"standard {num}: a reason of {len(text)} character(s), expected "
                    f"{NA_REASON_MIN_CHARS}..{NA_REASON_MAX_CHARS}")
        folded = " ".join(text.casefold().split())
        if folded in reasons:
            return f"standard {num}: the same reason is given for another standard"
        reasons.add(folded)
    return None


def not_applicable_cli(args: list[str]) -> int:
    """--not-applicable VERDICT N, the standards this client sent on stdin as a JSON array.
    Exit 0 with the comment's blockquote on stdout when VERDICT's standards_not_applicable
    is acceptable; exit 1 with the reason on stderr when it is not; 2 on bad usage."""
    if len(args) != 2 or not args[1].isdigit():
        sys.stderr.write("--not-applicable needs VERDICT N, the standards on stdin\n")
        return 2
    n = int(args[1])
    try:
        standards = json.loads(sys.stdin.read())
        verdict = json.loads(Path(args[0]).read_text())
    except (OSError, ValueError) as e:
        sys.stderr.write(f"   not-applicable list: unreadable ({e})\n")
        return 1
    if not isinstance(standards, list) or len(standards) != n or not isinstance(verdict, dict):
        sys.stderr.write(f"   not-applicable list: expected {n} standards and a verdict object\n")
        return 1
    rows = verdict.get("standards_not_applicable")
    problem = not_applicable_problem(rows, n)
    if problem is not None:
        why = verdict.get("standards_applicability_problem")
        sys.stderr.write(f"   not-applicable list refused: {problem}"
                         + (f" (broker: {_na_text(why)[:300]})" if why else "") + "\n")
        return 1
    labels = [f"> > - ({r['standard']}) {_na_text(standards[r['standard'] - 1])[:NA_LABEL_CHARS]}"
              f" → {_na_text(r['reason']).strip()}"
              for r in sorted(rows, key=lambda r: r["standard"])[:NA_LABEL_CAP]]
    if n > NA_LABEL_CAP:
        labels.append(f"> > - …and {n - NA_LABEL_CAP} more, not listed here")
    sys.stdout.write(
        "> ℹ️ No standard applies: **no project standard was applied**. The model named "
        f"none of the {n} standards as checked, and when asked about each one it judged it "
        "not applicable to this change, for the reason given. This pass means the change "
        "was read and nothing was flagged. It is not a rule check: read the reasons.\n>\n"
        + "\n".join(labels) + "\n\n")
    return 0


def _json_type(v: object) -> str:
    """The value's JSON type, named as jq's `type` names it."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    return {str: "string", list: "array", dict: "object"}.get(type(v), type(v).__name__)


def _one_line(v: object) -> str:
    return (v if isinstance(v, str) else json.dumps(v)).replace("\n", " ").replace("`", "'")


def unmatched_cli(args: list[str]) -> int:
    """--unmatched VERDICT REQUEST: the findings the broker marked `unmatched_file`, whose
    `file` is no changed or blast-radius path of REQUEST, are kept out of the verdict
    (CLAUDE.md section 4.8). Exit 0 with the comment's disclosure of them on stdout (empty
    when there are none); exit 1 when `findings` is not a list of objects, or when a mark
    sits on a path REQUEST did supply, because then the verdict left a real finding out and
    cannot be trusted; 2 on bad usage."""
    if len(args) != 2:
        sys.stderr.write("--unmatched needs VERDICT REQUEST\n")
        return 2
    try:
        verdict, req = (json.loads(Path(a).read_text()) for a in args)
        supplied = {str(f["path"]) for key in ("changed", "context")
                    for f in req.get(key) or [] if isinstance(f, dict) and f.get("path")}
        findings = verdict.get("findings")
        # The gate's only check of the findings shape; review-pr.sh calls this before jq
        # counts them, because jq's length reads a missing or null findings as 0 and a
        # string as its character count (geekspace #102, comment 29377). Here, not in
        # review-pr.sh, because that script is at its own DIFF_CAP (selftest
        # "installability"). A non-object entry is refused too, never skipped.
        if "findings" not in verdict:
            problem = "findings absent"
        elif not isinstance(findings, list):
            problem = f"findings is {_json_type(findings)}"
        else:
            problem = next((f"findings has an entry of type {_json_type(f)}" for f in findings
                            if not isinstance(f, dict)), None)
        if problem:
            sys.stderr.write(f"   broker verdict malformed: {problem}, expected a list of "
                             "finding objects\n")
            return 1
    except (OSError, ValueError, AttributeError) as e:
        sys.stderr.write(f"   unmatched findings: unreadable ({e})\n")
        return 1
    marked = [f for f in findings if f.get("unmatched_file") is True]
    wrong = sorted({f["file"] for f in marked if isinstance(f.get("file"), str)
                    and f["file"] in supplied})
    if wrong:
        sys.stderr.write(f"   broker marked a finding on {', '.join(wrong)} as naming no "
                         "supplied file, but this request supplied it: the verdict left it "
                         "out, so it cannot be trusted\n")
        return 1
    stale = sum(1 for f in findings if f.get("unmatched_file") is not True
                and not (isinstance(f.get("file"), str) and f["file"] in supplied))
    if stale:
        sys.stderr.write(f"   NOTE: {stale} finding(s) name no supplied file but are unmarked "
                         "and counted: the broker predates CLAUDE.md 4.8\n")
    if not marked:
        return 0
    sys.stderr.write(f"   unmatched findings: {len(marked)}, shown apart and not counted\n")
    sys.stdout.write(
        f"\n> **Not counted toward the verdict**: {len(marked)} finding(s) name no file this "
        "review was given (neither a changed file nor a dependent), so they cannot describe "
        "what this change did. Shown so nothing the model said is hidden:\n>\n"
        + "\n".join(f"> - `{_one_line(f.get('file'))}` — {_one_line(f.get('severity'))} / "
                     f"{_one_line(f.get('category'))}: {_one_line(f.get('summary'))}"
                     for f in marked) + "\n")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--jsonl-digest":
        return ledger_digest_cli(args[1:])
    if args and args[0] == "--not-applicable":
        return not_applicable_cli(args[1:])
    if args and args[0] == "--unmatched":
        return unmatched_cli(args[1:])
    as_json = "--json" in args
    declare_generated = "--declare-generated" in args
    args = [a for a in args if a not in ("--json", "--declare-generated")]
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

    deps, scanned, scan_errors, excluded = find_dependents(
        root, targets, rename_pairs, declare_generated)
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
    # Declared on every run that has one, in both output modes: see GENERATED_VIEWER_DIR.
    # Worded as a NOTE so it cannot be read as the INCOMPLETE warning above.
    for viewer, source in sorted(excluded):
        sys.stderr.write(f"NOTE: generated viewer not searched; its source was searched, "
                         f"or is a changed file under review: {viewer} (source {source})\n")
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
            "generated_excluded": [{"path": v, "source": s} for v, s in sorted(excluded)],
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
