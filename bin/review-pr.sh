#!/usr/bin/env bash
# WHAT: The Phase 3 PR gate client. Assembles a review request from a PR, sends it to the
#       review broker, and posts the verdict back to the forge as a comment.
# WHY:  This is the piece that runs in CI. It holds no model and no credentials to Ollama —
#       it can only ask the broker for a review, which is what preserves the isolation
#       invariant in CLAUDE.md section 3.
#
# ADVISORY BY DESIGN (2026-08-09). It posts findings and always exits 0 unless the gate
# itself malfunctioned. It does NOT block merges yet. James's call: run advisory until the
# false-positive rate is known, THEN wire into branch protection — otherwise the escape
# hatch built for an untrusted gate becomes permanent.
#
# Every stage reports what it examined, and refuses to report success on an empty scan —
# or on a PARTIAL one: an over-cap file diff, or a model that read fewer files than it was
# given, fails the gate rather than shipping a PASS that covers less than it claims.
#
# Usage: bin/review-pr.sh --pr N [--base main] [--repo owner/name] [--no-post]
set -euo pipefail

FORGE_API="${FORGE_API:-http://100.88.14.2:3300/api/v1}"
BROKER="${BROKER_URL:-http://100.88.14.2:3401}"
# Seconds the verdict-comment POST may take. Overridable so a test can prove the bound
# without waiting a minute; validated below, because curl -m with a non-number fails in a
# way that would read as a forge outage.
FORGE_POST_TIMEOUT="${FORGE_POST_TIMEOUT:-60}"
REPO="${REVIEW_REPO:-jfcadm/sovereign-forge}"
BASE="main"
PR=""
POST=1

while [ $# -gt 0 ]; do
  case "$1" in
    --pr) PR="$2"; shift 2 ;;
    --base) BASE="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --no-post) POST=0; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$PR" ] || { echo "usage: $(basename "$0") --pr N [--base main] [--no-post]" >&2; exit 2; }

die() { echo "GATE ERROR: $*" >&2; exit 1; }
# Digits alone are not enough: curl -m reads 00 or 000 as 0, which means NO limit.
case "$FORGE_POST_TIMEOUT" in
  ''|*[!0-9]*) die "FORGE_POST_TIMEOUT='$FORGE_POST_TIMEOUT' is not a positive whole number of seconds" ;;
  *[1-9]*) ;;
  *) die "FORGE_POST_TIMEOUT='$FORGE_POST_TIMEOUT' is not a positive whole number of seconds" ;;
esac

# Every count this gate reads from the broker goes through here. Digits-only is NOT
# sufficient on its own: a JSON integer beyond the shell's signed range (say
# 9223372036854775808) satisfies a *[!0-9]* allowlist, and every later `[ x -gt y ]` on
# it then fails with "integer expression expected" and evaluates FALSE -- so an
# impossible count slips every comparison meant to catch it and a PASS is posted
# (Codex [P2] on PR #71, fifth round). Bounding the DIGIT COUNT closes the whole class
# rather than the one value that demonstrated it: nine digits is a billion files or
# standards, orders of magnitude past anything real and far inside the comparable range.
# $1 = value, $2 = the broker field name, $3 = the rest of the refusal message.
MAX_COUNT_DIGITS=9
require_count() {
  case "$1" in
    ''|*[!0-9]*) die "broker reported $2='$1', which is not a count — $3" ;;
  esac
  if [ "${#1}" -gt "$MAX_COUNT_DIGITS" ]; then
    die "broker reported $2='$1', which is too large to be a count this gate can compare — $3"
  fi
}

# Credentials come from files or the CI environment, and reach curl through a mode-0600
# header file (-H @file), never on argv — argv is world-readable through a process list
# for the whole life of the request, which for the broker call is up to 900s. This
# comment used to describe an intention the code did not implement: both tokens were
# interpolated straight into curl's argument list (Codex [P2]).
FT="${FORGE_TOKEN:-$(cat "$HOME/.config/sovereign-forge/token" 2>/dev/null || true)}"
BT="${BROKER_TOKEN:-}"
if [ -z "$BT" ] && [ -r "$HOME/.config/sovereign-forge/broker.env" ]; then
  set -a
  # shellcheck source=/dev/null
  . "$HOME/.config/sovereign-forge/broker.env"
  set +a; BT="${BROKER_TOKEN:-}"
fi
# The forge credential is spent ONLY on the comment POST below. Demanding it up
# front also fired in --no-post mode, which is documented in the usage line and
# needs nothing but the broker — so a valid local review died on a credential it
# was never going to use (Codex [P3]). Still checked before the 900s broker call
# rather than after it: a review nobody can post is worth failing fast on.
if [ "$POST" -eq 1 ] && [ -z "$FT" ]; then
  die "no forge token — needed to post the review comment (pass --no-post to print it instead)"
fi

HEAD_SHA=$(git rev-parse HEAD)
echo "── reviewing $REPO PR #$PR at ${HEAD_SHA:0:8} (base $BASE)"

# ---- 1. changed files. An empty diff is UNKNOWN, never a pass. --------------------
# NOT `git diff --name-only`: for a detected rename that prints only the DESTINATION,
# so the old path never reaches the model and never reaches the blast-radius scan. The
# file then renders as a plain addition and every caller still importing the old name
# goes unexamined — a rename that breaks its callers earns a clean verdict. Observed on
# mcp-techkb PR #13, which carried an R100 of .github/workflows/secret-scan.yml to
# .forgejo/ and was passed by this gate with the defect in force (Codex [P1], 2026-08-29).
#
# --name-status -z gives both halves. Rename detection stays ON deliberately: the loop in
# 4a diffs ONE path at a time, and a path-limited diff is resolved BEFORE renames are
# paired up, so the old path yields its full deletion diff and the new path its full
# addition diff — both reviewed in full. Asking for both paths in a SINGLE diff is what
# collapses to a 197-byte "similarity index 100%" stub that reviews nothing, and that is
# why --no-renames is not the fix here.
#
# -z because the status and paths are NUL-delimited: a path containing a space, a quote
# or a newline is legal in git and would otherwise be split or shell-quoted into a name
# that matches no file on disk.
#
# -M -C -l0 because detection must not depend on the consuming repo's git config: each
# flag closes a different way the config turns it off, all measured on git 2.50.1.
#   -M   under diff.renames=false a move emits separate D/A records and the rename is
#        invisible again — the defect above wearing a different hat.
#   -C   -M ALONE overrides diff.renames=copies and turns a detected copy back into a
#        plain addition, silently disabling the C branch below.
#   -l0  diff.renameLimit caps the exhaustive pass: at renameLimit=1 a fixture of four
#        moved-and-edited files dropped from 4 R records to 0 even WITH -M -C. Applies
#        to INEXACT renames (moved AND edited); an exact rename is paired in a cheap
#        pre-pass no limit touches, so the R100 above was never at risk — "moved it and
#        tweaked it" is, and is the more common shape.
# mcp-techkb and astgl-articles get a byte-identical copy of this script, so their local
# git config is not part of its contract (Codex [P2], 2026-08-29).
CHANGED=()
CHANGED_STATUS=()
while IFS= read -r -d '' _st; do
  IFS= read -r -d '' _p1 \
    || die "git diff --name-status ended mid-record after status '$_st' — refusing to review a truncated file list"
  case "$_st" in
    R*)
      # Rename: <status>\0<source>\0<destination>\0. Both are reviewed, and each side's
      # status names the other so the model can see the move rather than a coincidental
      # delete-plus-add.
      IFS= read -r -d '' _p2 \
        || die "git diff --name-status gave '$_st' for '$_p1' with no destination path — refusing to review a truncated file list"
      CHANGED+=("$_p1"); CHANGED_STATUS+=("deleted by rename to $_p2")
      CHANGED+=("$_p2"); CHANGED_STATUS+=("added by rename from $_p1")
      ;;
    C*)
      # COPY is not a rename: the source still exists and still says what it said, so
      # only the DESTINATION is part of this change. Lumping C in with R labelled a
      # live file "deleted by rename" — false metadata handed to the model — and
      # submitted its path-limited diff, which is empty, as a file the model would
      # still count as examined (Codex [P2], 2026-08-29). Only reachable when copy
      # detection is on (diff.renames=copies or -C), hence latent until now.
      IFS= read -r -d '' _p2 \
        || die "git diff --name-status gave '$_st' for '$_p1' with no destination path — refusing to review a truncated file list"
      CHANGED+=("$_p2"); CHANGED_STATUS+=("added by copy from $_p1")
      ;;
    A*) CHANGED+=("$_p1"); CHANGED_STATUS+=("added") ;;
    D*) CHANGED+=("$_p1"); CHANGED_STATUS+=("deleted") ;;
    T*) CHANGED+=("$_p1"); CHANGED_STATUS+=("typechange") ;;
    *)  CHANGED+=("$_p1"); CHANGED_STATUS+=("modified") ;;
  esac
done < <(git diff --name-status -z -M -C -l0 "$BASE...HEAD")

# ---- 1b. generated artifacts: excluded from review, never silently ----------------
# WHY: /doco-refresh commits an Archify system map as THREE files — a typed JSON IR (the
# authored source), an extracted SVG, and a ~700KB compiled HTML viewer. Measured on
# mcp-personal-context PR #18: the HTML diff is 728,469 bytes — 12x the 60,000-byte
# per-file cap below and 1.8x the broker's entire 400,000-byte budget. Every docs PR
# therefore died at the cap with no verdict and forge-pr fell closed on the missing
# verdict: precisely the "merge blocked by arithmetic nobody could see" failure the cap's
# own comment warns about, now arriving on every PR of a whole class.
#
# THREAT MODEL (verified 2026-08-31 against the forge API: jfcadm repos report forks=0,
# collaborators=0, private=true). The adversary here is an owner ACCIDENT, not a
# malicious contributor smuggling code past review. An exclusion sized for that threat
# is narrow and conditional; it is NOT a general "large files are exempt" escape, which
# would be a real hole and is deliberately not what this is.
#
# Two conditions, BOTH required:
#   1. the path is docs/diagrams/*.architecture.html — a shape this fleet only ever
#      generates and never hand-authors;
#   2. the sibling <name>.architecture.json IR is ALSO in this PR's changed set, so the
#      reviewable SOURCE of that artifact is under review in the same change.
#
# Condition 2 is the load-bearing one. A hand-edited HTML whose IR did not change is not
# paired, stays in CHANGED, and still dies at the cap — so the artifact can only be
# skipped when the thing it is compiled from is being read. Dropping condition 2 would
# turn this into the blanket exemption above.
#
# Excluded paths are REMOVED from CHANGED, so the "every changed file must be read" check
# further down stays true of the files actually submitted rather than being quietly
# widened. They are then DECLARED on stdout and in the posted comment: an undeclared
# exclusion reads as "covered everything", which is the failure this whole gate exists to
# prevent. Removal happens BEFORE the empty-set check below on purpose — a PR that
# somehow contained only generated artifacts would land on "refusing to report a clean
# review of nothing" rather than sailing through having reviewed zero files.
GENERATED=(); GENERATED_BYTES=()
_KEPT=(); _KEPT_STATUS=()
_GT=$(mktemp)
for _i in "${!CHANGED[@]}"; do
  _f="${CHANGED[$_i]}"; _s="${CHANGED_STATUS[$_i]}"
  _paired=0
  case "$_f" in
    docs/diagrams/*.architecture.html)
      _ir="${_f%.html}.json"
      for _c in "${CHANGED[@]}"; do
        if [ "$_c" = "$_ir" ]; then _paired=1; break; fi
      done
      ;;
  esac
  if [ "$_paired" -eq 1 ]; then
    git diff "$BASE...HEAD" -- "$_f" > "$_GT"
    GENERATED+=("$_f")
    GENERATED_BYTES+=("$(wc -c < "$_GT" | tr -d '[:space:]')")
  else
    _KEPT+=("$_f"); _KEPT_STATUS+=("$_s")
  fi
done
rm -f "$_GT"
# ${arr[@]+"${arr[@]}"} — an empty array under `set -u` is an unbound-variable error on
# bash < 4.4, and the runner's bash is not pinned. Reachable whenever a PR is nothing but
# paired artifacts, which the empty-set check below is there to refuse.
CHANGED=(${_KEPT[@]+"${_KEPT[@]}"}); CHANGED_STATUS=(${_KEPT_STATUS[@]+"${_KEPT_STATUS[@]}"})

[ "${#CHANGED[@]}" -gt 0 ] || die "no files changed vs $BASE — refusing to report a clean review of nothing"
echo "   changed: ${#CHANGED[@]} path(s)"
GENERATED_NOTE=""
if [ "${#GENERATED[@]}" -gt 0 ]; then
  echo "   generated: ${#GENERATED[@]} artifact(s) EXCLUDED from review (their IR is reviewed instead):"
  for _i in "${!GENERATED[@]}"; do
    echo "     - ${GENERATED[$_i]} (${GENERATED_BYTES[$_i]} bytes; source ${GENERATED[$_i]%.html}.json)"
    GENERATED_NOTE="${GENERATED_NOTE}- \`${GENERATED[$_i]}\` (${GENERATED_BYTES[$_i]} bytes) — reviewed via its source \`${GENERATED[$_i]%.html}.json\`
"
  done
fi

# ---- 2. blast radius. Its own positive control; non-zero exit means UNKNOWN. ------
# GATE_BIN lets a CI job run the resolver from somewhere OTHER than the reviewed tree.
# It matters under pull_request_target, where the workflow re-materializes the gate
# scripts from the protected base precisely so the PR cannot supply the executable that
# reviews it: with the path hardcoded to bin/, that job would pin review-pr.sh and then
# run the PR's OWN bin/blast-radius.py, with the forge and broker tokens in scope.
# Ported from claude-memory, the one consumer using that trigger; defaults to bin/, so
# every pull_request consumer is unaffected.
BR_JSON=$("${GATE_BIN:-bin}/blast-radius.py" --json --changed-from "$BASE") \
  || die "blast-radius resolver failed its positive control — dependency scan is UNKNOWN, not empty"
BR_COUNT=$(echo "$BR_JSON" | jq '.blast_radius | length')
BR_SCANNED=$(echo "$BR_JSON" | jq '.files_scanned')
# Tracked files the resolver could NOT search (over its size limit, or not text) are
# counted here and carried to section 6. The resolver reports them and exits 0 on
# purpose -- see its main() -- so they never become dependents, never enter the context
# loop, and none of CTX_SKIPPED / CTX_TRUNCATED / CTX_OMITTED can see them. Without this
# the comment claimed "No findings in the changed code or its blast radius" over a sweep
# the resolver itself had called INCOMPLETE (Codex, round 4 of jfcadm/claude-config PR #31).
# Every shape is mapped, not just the expected one: an array is its length; absent, null
# or any other type is UNKNOWN (-1), and unknown drops the all-clear exactly like a
# nonzero count. Advisory like the rest: disclosed, never fatal.
BR_UNREADABLE=$(echo "$BR_JSON" | jq 'if (.unreadable|type) == "array" then (.unreadable|length) else -1 end') \
  || die "could not read the resolver's unreadable-file count"
echo "   blast radius: $BR_COUNT dependent(s) from $BR_SCANNED file(s) scanned"
if [ "$BR_UNREADABLE" -gt 0 ]; then
  echo "   blast radius: $BR_UNREADABLE tracked file(s) could not be read and were never searched — this blast radius is INCOMPLETE"
elif [ "$BR_UNREADABLE" -lt 0 ]; then
  echo "   blast radius: the resolver did not report its unreadable files — completeness is UNKNOWN"
fi

# Context FILE-COUNT budget — independent of the byte budget below. The broker enforces
# TWO separate caps (review-broker.py MAX_BYTES=400,000 OR MAX_FILES=120, either one
# fails the request), and a large blast radius can blow the file-count cap even once the
# byte cap is satisfied (found 2026-08-17 testing PR jfcadm/claudeclaw#931 against this
# fix: 184 dependents + 4 changed = 188 files, comfortably under budget in bytes at
# 327,563, still hard-rejected at 188 > 120). Cap context to whatever's left of the
# 120-file budget after the actual changed files, which must never be dropped. The
# selection below is blast-radius.py's own output order (alphabetical — see its `sorted()`
# in main()), not a relevance ranking; a smarter "closest to the change" ordering would
# be a real improvement but isn't built yet — this is a known simplification, not a
# considered design. Reported explicitly on the console line in step 4b rather than silently
# — a partial-context PR should be visible to whoever reads the CI log, even though
# (unlike the diff itself) losing some context files is a real, defensible degradation
# rather than the "reviewed less than it claimed" failure mode this project keeps hitting.
MAX_CONTEXT_FILES_CAP=120
CONTEXT_FILE_LIMIT=$((MAX_CONTEXT_FILES_CAP - ${#CHANGED[@]}))
if [ "$CONTEXT_FILE_LIMIT" -lt 0 ]; then
  CONTEXT_FILE_LIMIT=0
fi

# ---- 3. standards, lifted from the project's own CLAUDE.md -----------------------
# The differentiator: this gate enforces rules that live in this repo, which no external
# reviewer can see. A missing or empty standards list is a real degradation, so say so.
# The section markers are env-configurable because consuming repos number their CLAUDE.md
# headings differently (astgl-articles has no "## 3." — its standards live under a named
# heading). Defaults preserve this repo's behaviour byte-for-byte.
STANDARDS_BEGIN="${STANDARDS_BEGIN:-^## 3\\.}"
STANDARDS_END="${STANDARDS_END:-^## 4\\.}"
# Read from the BASE ref, not the worktree. The ruleset a review is judged against must
# not be attacker-controlled: under pull_request_target the worktree IS the PR, so a PR
# could rewrite CLAUDE.md to a permissive list and be graded against its own rules. The
# CLAUDE.md diff still reaches the reviewer as part of the change; what is pinned here is
# the yardstick. Falls back to the worktree copy when the base has none, which is the
# bootstrap PR that introduces it.
#
# Bullets are joined with their continuation lines before extraction. Emitting only the
# first physical line dropped the very clauses that carry the rule while still counting
# the fragment as a checked standard, so a PR could violate a continuation-only
# requirement and get an all-clear. A blank line, the next bullet, or the end marker
# closes a bullet. Repos whose bullets are already one line (this one, mcp-techkb,
# viceroy) are unaffected: measured, their extraction is byte-identical either way.
_STD_SRC=$(git show "$BASE:CLAUDE.md" 2>/dev/null) || _STD_SRC=""
[ -n "$_STD_SRC" ] || _STD_SRC=$(cat CLAUDE.md 2>/dev/null || true)
STANDARDS=$(printf '%s\n' "$_STD_SRC" \
            | awk -v b="$STANDARDS_BEGIN" -v e="$STANDARDS_END" '
                function flush() { if (cur != "") { print cur; cur="" } }
                $0 ~ b { f=1; next }
                f && $0 ~ e { flush(); f=0 }
                f && /^- \*\*/ { flush(); cur=$0; next }
                f && cur != "" && /^[[:space:]]+[^[:space:]]/ {
                    line=$0; sub(/^[[:space:]]+/, " ", line); cur=cur line; next }
                f && cur != "" { flush() }
                END { flush() }' \
            | sed 's/^- \*\*//; s/\*\*//g' | jq -R . | jq -s .)
# No per-standard truncation. cut -c1-300 cut real rules mid-clause (the longest in the
# fleet is ~1600 chars) and dropped the later clauses that carry them, while still
# counting the fragment as checked. The request TOTAL is bounded instead, below.
STD_COUNT=$(echo "$STANDARDS" | jq 'length')
# Zero standards is a FAILED gate, not a degraded one. A verdict produced without any
# project standards is a generic review wearing this gate's badge, and the whole point is
# enforcing rules that live in this repo. Same family as every other zero-scan in here:
# UNKNOWN, never clean. (Found by the gate reviewing its own diff — rated minor, and the
# only genuine finding in that batch.)
[ "$STD_COUNT" -gt 0 ] \
  || die "extracted ZERO standards from CLAUDE.md — refusing to pass off a generic review as this gate"
echo "   standards: $STD_COUNT extracted from CLAUDE.md"

# ---- 4a. the changed-file diffs, MEASURED as they are built -----------------------
REQ=$(mktemp); DTMP=$(mktemp); CJSON=$(mktemp); trap 'rm -f "$REQ" "$DTMP" "$CJSON"' EXIT
# The context budget in 4b is derived from this measurement instead of a fixed guess
# at what the diff would cost. It used to be a guess: CONTEXT_BUDGET was a flat
# 300,000, which silently assumed the diff plus everything else would fit in the
# remaining 100,000. But the per-file diff cap is 60,000 and the changed-file count is
# unbounded, so two large changed files plus a routine ten-dependent blast radius came
# to ~420,000 against the broker's 400,000. The broker refuses rather than trims, so
# the whole request is rejected, the gate dies with no verdict, and forge-pr fails
# closed on the missing verdict — a merge blocked by arithmetic nobody could see.
# Codex [P2].
# The per-file cap is DERIVED from the broker's own budget rather than picked. A flat
# 60,000 made the gate UNINSTALLABLE: this gate's own bin/blast-radius.py crossed that
# line on 2026-08-30 (84ac987, 60,261 bytes) and a fresh install PR carries it as a
# 61,500-byte new-file diff, so review-pr.sh refused to review the PR that installs
# review-pr.sh. Nobody noticed because no repo had been onboarded since that date.
#
# A quarter of the request budget is the rule: no single file may consume more than 25%
# of what the broker will accept, which leaves room for at least three more changed
# files plus the standards and blast radius before the whole-request check below fires.
# The cap's PURPOSE is unchanged and does not depend on the number — it refuses to send
# a truncated diff while claiming the file was examined. Only the threshold moves, and
# it now moves automatically if the broker's budget ever does, instead of silently
# drifting out of proportion to it the way the flat value did.
#
# BROKER_MAX_BYTES is defined in 4b below, after this block. It is repeated as a literal
# here ON PURPOSE rather than reordered: 4b's value is the one the whole-request check
# uses, and moving it up to satisfy this arithmetic would put the definition far from the
# comment explaining how it is kept in sync with review-broker.py. The guard immediately
# after keeps the two honest, so a future edit to one that forgets the other FAILS rather
# than quietly re-introducing a hand-picked cap.
DIFF_CAP=$(( 400000 / 4 ))
DIFF_BYTES=0
{
  first=1
  for i in "${!CHANGED[@]}"; do
    f="${CHANGED[$i]}"; st="${CHANGED_STATUS[$i]}"
    [ $first -eq 1 ] || echo ','
    first=0
    # Written to a FILE, never `git diff … | head -c`: head closes the pipe once it
    # has its cap, git takes SIGPIPE, and `set -euo pipefail` turns that into exit
    # 141 that kills the WHOLE gate. Any PR carrying a single-file diff larger than
    # the cap therefore died here, before the broker was ever called — the gate
    # produced no review at all while reporting a plain CI failure. Observed on
    # claudeclaw #944: three runs at three different heads, all exit 141 immediately
    # after "standards: N extracted", misdiagnosed for a week as an Ollama outage.
    git diff "$BASE...HEAD" -- "$f" > "$DTMP"
    fsz=$(wc -c < "$DTMP" | tr -d '[:space:]')
    # An over-cap diff FAILS THE GATE; it is never sent as a prefix. `head -c` used to
    # silently drop every hunk past byte 60,000 while the request still listed the file
    # as supplied and the model still counted it as examined — so a defect at byte
    # 60,001 produced a PASS / "No findings" comment that satisfied forge-pr. That is
    # the same "reviewed less than it claimed" failure the whole-request check below
    # was written against, arriving one level down (Codex [P1], 2026-08-29). Refusing
    # here is what keeps truncation visible in the verdict instead of silent.
    if [ "$fsz" -gt "$DIFF_CAP" ]; then
      die "$f: diff is $fsz bytes, past the ${DIFF_CAP}-byte per-file cap — split the PR. Sending its first $DIFF_CAP bytes would review less than it claims while still reporting the file as examined, which is the failure this gate exists to prevent"
    fi
    # The diff goes to jq STRAIGHT FROM THE FILE. `d=$(cat "$DTMP")` stripped the
    # trailing newline — command substitution always does — so the last byte of every
    # single diff was dropped while the file was still reported as fully supplied.
    # One byte is not a defect anyone will hit, but it is the same shape as the cap
    # above: send less than is claimed. Measured on a 56,118-byte fixture diff, 56,117
    # arrived. Reading the file twice also removes the need to keep $d and $fsz in step.
    #
    # Counted in BYTES while the broker counts CHARACTERS of the decoded string
    # (review-broker.py sums len() over the parsed diff/content fields). For UTF-8
    # bytes >= characters, so this over-states the cost and can only err toward
    # sending less than the cap allows, never more.
    DIFF_BYTES=$(( DIFF_BYTES + fsz ))
    # jq -Rs, not -R, on the path and the status. -R reads raw input LINE BY LINE, so a
    # value containing a newline comes out as TWO JSON strings and the request stops
    # parsing — `jq: parse error` and a gate that dies with no verdict on a filename git
    # is perfectly happy with. Reachable since --name-status -z started handing over raw
    # paths (--name-only used to pre-quote them into "we\nird.py"), and reachable for the
    # status too, which now carries a rename's counterpart path. Fails closed, so it was
    # never a coverage lie — but a legitimate path should not break the gate.
    printf '{"path":%s,"status":%s,"diff":%s}' "$(printf '%s' "$f" | jq -Rs .)" "$(printf '%s' "$st" | jq -Rs .)" "$(jq -Rs . < "$DTMP")"
  done
} > "$CJSON"

# ---- 4b. context BYTE budget: what is left once the diff is paid for --------------
# Keep BROKER_MAX_BYTES in sync with review-broker.py's MAX_BYTES by inspection — they
# are separate processes with no shared import, the same coupling family as the gate's
# comment template and forge-pr's parser (CLAUDE.md section 3). The margin is headroom
# against that constant drifting, not against the measurement, which is already
# conservative for the reason above.
BROKER_MAX_BYTES=400000
# DIFF_CAP above is derived from this number by hand (it is needed earlier in the file).
# Assert the two still agree rather than trusting a comment: a silent divergence would
# restore exactly the hand-picked cap this change removed.
[ "$DIFF_CAP" -eq "$(( BROKER_MAX_BYTES / 4 ))" ] \
  || die "DIFF_CAP=$DIFF_CAP is no longer BROKER_MAX_BYTES/4=$(( BROKER_MAX_BYTES / 4 )) — one was edited without the other; refusing to review against a cap nobody chose"
BROKER_SAFETY_MARGIN=20000
CONTEXT_CAP=30000
CONTEXT_CAP_MIN=500
REQUEST_ALLOWANCE=$(( BROKER_MAX_BYTES - BROKER_SAFETY_MARGIN ))
if [ "$DIFF_BYTES" -gt "$REQUEST_ALLOWANCE" ]; then
  die "the changed-file diffs alone are $DIFF_BYTES bytes, past the broker's ${BROKER_MAX_BYTES}-byte cap — split the PR. Trimming the diff to fit would review less than it claims, which is the failure this gate exists to prevent"
fi
# Standards ride in the same request as the diff and the context, so they have to come
# out of the same allowance. This used to be unaccounted, which the safety margin quietly
# absorbed; now that whole bullets are sent rather than 300-char prefixes, the payload is
# several KB and guessing is no longer good enough.
STD_BYTES=$(printf '%s' "$STANDARDS" | wc -c | tr -d ' ')
if [ "$(( DIFF_BYTES + STD_BYTES ))" -gt "$REQUEST_ALLOWANCE" ]; then
  die "the changed-file diffs plus this repo's standards are $(( DIFF_BYTES + STD_BYTES )) bytes, past the broker's ${BROKER_MAX_BYTES}-byte cap — split the PR"
fi
CONTEXT_BUDGET=$(( REQUEST_ALLOWANCE - DIFF_BYTES - STD_BYTES ))
if [ "$BR_COUNT" -gt 0 ]; then
  SHARE=$(( CONTEXT_BUDGET / BR_COUNT ))
  if [ "$SHARE" -lt "$CONTEXT_CAP_MIN" ]; then
    # The budget cannot give every dependent a useful slice. Send FEWER files at the
    # floor rather than more files over budget: raising the per-file cap back up to
    # the floor is precisely what could push the total past the broker's limit, so
    # the file count has to absorb it. (Letting SHARE stand would mean `head -c 0` —
    # every context file present but empty, pointless rather than merely small.)
    CONTEXT_CAP=$CONTEXT_CAP_MIN
    BYTE_FILE_LIMIT=$(( CONTEXT_BUDGET / CONTEXT_CAP_MIN ))
    if [ "$BYTE_FILE_LIMIT" -lt "$CONTEXT_FILE_LIMIT" ]; then
      CONTEXT_FILE_LIMIT=$BYTE_FILE_LIMIT
    fi
  elif [ "$SHARE" -lt "$CONTEXT_CAP" ]; then
    CONTEXT_CAP=$SHARE
  fi
fi
# Every branch above holds files_sent * CONTEXT_CAP <= CONTEXT_BUDGET, so the assembled
# request totals at most REQUEST_ALLOWANCE.
# Omitted dependents are COUNTED for section 6, not only echoed here. The console line was
# the sole record, so a comment could claim a clean blast radius that the file limit had
# cut short (Codex [P2] on jfcadm/claude-config PR #27).
CTX_OMITTED=0
if [ "$BR_COUNT" -gt "$CONTEXT_FILE_LIMIT" ]; then
  CTX_OMITTED=$(( BR_COUNT - CONTEXT_FILE_LIMIT ))
  echo "   context: capping to $CONTEXT_FILE_LIMIT/$BR_COUNT blast-radius file(s) ($CTX_OMITTED omitted)"
fi
echo "   budget: diff $DIFF_BYTES B; standards $STD_BYTES B; context <= $CONTEXT_BUDGET B at <= $CONTEXT_CAP B/file (broker cap $BROKER_MAX_BYTES B)"

# ---- 4c. assemble -----------------------------------------------------------------
# Dependents the loop below refuses are COUNTED, not just logged. A skipped path leaves
# BR_COUNT untouched while never reaching the broker, so files_examined can equal
# files_supplied_total -- "everything supplied was read" -- for a review that silently
# omitted a dependent, and section 6 would then claim the whole blast radius clean
# (Codex [P2] on PR #71). The braces below are not a subshell, so the count survives.
#
# Dependents larger than CONTEXT_CAP are counted the same way. Only their prefix is sent,
# and the model can "read" every supplied prefix, so files_examined == files_supplied_total
# holds while most of the file never reached it (same Codex [P2] as CTX_OMITTED above).
CTX_SKIPPED=0
CTX_TRUNCATED=0
{
  echo '{'
  echo "\"head_sha\": $(printf '%s' "$HEAD_SHA" | jq -R .),"
  echo "\"standards\": $STANDARDS,"
  echo '"changed": ['
  cat "$CJSON"
  echo '],'
  echo '"context": ['
  first=1
  # NUL-delimited, not word-split. `for f in $(...)` splits on IFS, so a dependent
  # path containing a space or a glob character arrived as fragments, every fragment
  # failed the readability test, and the file was dropped -- a verdict posted without
  # a dependent that BR_COUNT had already counted as found. Ported from claude-memory,
  # whose fork carried this fix while every other consumer word-split.
  while IFS= read -r -d '' f; do
    # Regular files only, and never a symlink. `head` FOLLOWS a symlink, and
    # actions/checkout persists the forge token into .git/config, so a tracked
    # symlink pointing at it would ship that credential to the broker inside an
    # ordinary-looking context file. `-r` alone passes such a symlink happily.
    # -L is tested BEFORE -f because a symlink to a regular file also satisfies -f.
    if [ -L "$f" ] || [ ! -f "$f" ] || [ ! -r "$f" ]; then
      echo "   context: skipping non-regular or unreadable path: $f" >&2
      CTX_SKIPPED=$(( CTX_SKIPPED + 1 ))
      continue
    fi
    [ $first -eq 1 ] || echo ','
    first=0
    fsize=$(wc -c < "$f") || die "could not size context file $f"
    if [ "$(( fsize ))" -gt "$CONTEXT_CAP" ]; then
      CTX_TRUNCATED=$(( CTX_TRUNCATED + 1 ))
    fi
    # -Rs on the path for the same reason as the changed-file entry above. `--` ends
    # option parsing: a path beginning with a dash is otherwise read by head as a flag.
    printf '{"path":%s,"content":%s}' "$(printf '%s' "$f" | jq -Rs .)" "$(head -c "$CONTEXT_CAP" -- "$f" | jq -Rs .)"
  done < <(echo "$BR_JSON" | jq -j --argjson n "$CONTEXT_FILE_LIMIT" '.blast_radius[:$n][] | . + "\u0000"')
  echo ']}'
} > "$REQ"
jq -e . "$REQ" >/dev/null || die "assembled an invalid request JSON"
if [ "$CTX_SKIPPED" -gt 0 ]; then
  echo "   context: $CTX_SKIPPED dependent(s) were refused as non-regular or unreadable and never sent — this blast radius is INCOMPLETE"
fi
if [ "$CTX_TRUNCATED" -gt 0 ]; then
  echo "   context: $CTX_TRUNCATED dependent(s) exceeded ${CONTEXT_CAP} B and were sent truncated — this blast radius is PARTIAL"
fi

# ---- 5. ask the broker ------------------------------------------------------------
V=$(mktemp); BHDR=$(mktemp); trap 'rm -f "$REQ" "$DTMP" "$CJSON" "$V" "$BHDR"' EXIT
# mktemp creates 0600 (verified on BSD and GNU coreutils), so the token is readable
# only by this user -- unlike argv. An unauthenticated broker leaves the file empty,
# which curl accepts as "no extra headers".
if [ -n "$BT" ]; then printf 'Authorization: Bearer %s\n' "$BT" > "$BHDR"; fi
code=$(curl -sS -m 900 -o "$V" -w '%{http_code}' -X POST \
       -H @"$BHDR" -H 'Content-Type: application/json' \
       --data-binary @"$REQ" "$BROKER/review") || die "broker unreachable at $BROKER"

VERDICT=$(jq -r '.verdict // "error"' "$V")
if [ "$VERDICT" = "error" ] || [ "$code" != "200" ]; then
  die "broker returned $code / verdict=$VERDICT :: $(jq -r '.error // "no detail"' "$V")"
fi

EXAMINED=$(jq -r .files_examined "$V"); SUBMITTED=$(jq -r .files_supplied_total "$V")
EXAMINED_CHANGED=$(jq -r .files_examined_changed "$V")
STD_CHECKED=$(jq -r '.standards_checked' "$V"); STD_SUPPLIED=$(jq -r '.standards_supplied' "$V")
FINDINGS=$(jq '.findings | length' "$V")
echo "   verdict: $VERDICT — $FINDINGS finding(s), examined $EXAMINED/$SUBMITTED supplied file(s) ($EXAMINED_CHANGED/${#CHANGED[@]} changed), $STD_CHECKED/$STD_SUPPLIED standard(s)"

# The standards ratio is ENFORCED, not just rendered into the comment. This gate's whole
# claim is that it applies rules living in THIS repo; a verdict that skipped them is a
# generic review wearing the badge, which is the same failure the zero-standard check
# already refuses at the other end of the pipe. Ported from claude-memory.
#
# Same digits-only allowlist as the file counts above, and for the same reason: "null"
# from a broker that never sent the field must read as UNKNOWN, not as zero.
require_count "$STD_SUPPLIED" standards_supplied "whether this repo's rules were applied is UNKNOWN, never clean"
require_count "$STD_CHECKED" standards_checked "whether this repo's rules were applied is UNKNOWN, never clean"
# Sent N, received M: a mismatch means standards were lost in transit, so the review was
# graded against a ruleset this client never chose.
if [ "$STD_SUPPLIED" != "$STD_COUNT" ]; then
  die "broker received $STD_SUPPLIED standard(s) but this client sent $STD_COUNT — standards lost in transit; UNKNOWN, refusing"
fi
# More checked than supplied is not a better review, it is an impossible number.
# Gated on a merge-eligible verdict for the same reason every other count guard here
# is: the broker does NOT clamp this model-reported number, a non-pass verdict cannot
# merge anyway, and killing it would discard real findings over a counting mistake.
# Leaving it ungated repeated, in this very change, the flaw its own commit message
# criticised in claude-memory (Codex [P2] on PR #71, third round).
if [ "$VERDICT" = "pass" ] && [ "$STD_CHECKED" -gt "$STD_SUPPLIED" ]; then
  die "broker reports $STD_CHECKED standard(s) checked of $STD_SUPPLIED supplied — an impossible ratio; UNKNOWN, refusing"
elif [ "$STD_CHECKED" -gt "$STD_SUPPLIED" ]; then
  echo "   NOTE: broker reports $STD_CHECKED standard(s) checked of $STD_SUPPLIED supplied — an impossible ratio; the findings stand, the ratio does not"
fi
# A PASS that checked only SOME of the rules is REPORTED, not refused. Measured against
# live traffic before this was written: viceroy PR #16 merged on a real verdict of 2/12
# standards checked, and claude-memory's fork -- where this port came from -- would have
# killed it. Partial standards coverage is ordinary model behaviour, not an anomaly, and
# a gate that fails most real PRs gets worked around, which costs more than the gap it
# closes. The ratio is already rendered into the posted comment, so the human sees it.
# Same posture as #68 took for a clamped aggregate: say it, do not die on it.
# ZERO checked is not the mild end of partial, it is the generic review this gate exists
# to refuse -- the same thing section 3 already dies on when the extraction comes back
# empty, arriving from the other end of the pipe. forge-pr decides on the verdict word and
# never reads this ratio, so nothing downstream would catch it (Codex [P2] on PR #71).
# The live-traffic evidence that motivated the softening was 2/12, 10/10 and 11/11 -- all
# non-zero -- so refusing exactly zero costs none of it.
# Docs-only PRs are the ONE exception to the zero-standards refusal, and it is decided here
# from this client's own paths, never from the broker's docs_only flag. Every standard in a
# repo like this one is about code, so on a PR that changes only documentation the model
# answers truthfully that none apply: 0 of N, even from the WHICH follow-up, and even
# when a "not-applicable still counts" wording is used (measured 2026-09-25 on #98). Refusing
# that blocked every docs PR since b0b2c62. Accepted only when every changed file was named
# as read, and never silently: the comment says no project rule was applied (STD_ZERO_DOCS).
# DOC_SUFFIXES must match review-broker.py's by inspection. No txt: requirements.txt and
# CMakeLists.txt are build inputs (Codex [P2], #101). Lowercased through tr because
# macOS bash 3.2 has no ${x,,}.
DOC_SUFFIXES="md markdown rst"
DOCS_ONLY=0
if [ "${#CHANGED[@]}" -gt 0 ]; then
  DOCS_ONLY=1
  for _f in "${CHANGED[@]}"; do
    _ext=$(printf '%s' "${_f##*/}" | tr '[:upper:]' '[:lower:]')
    case "$_ext" in *.*) _ext="${_ext##*.}" ;; *) _ext="" ;; esac
    # An empty extension becomes "  ", which the single-spaced list never contains.
    case " $DOC_SUFFIXES " in
      *" $_ext "*) ;;
      *) DOCS_ONLY=0; break ;;
    esac
  done
fi
STD_ZERO_DOCS=0
if [ "$VERDICT" = "pass" ] && [ "$STD_SUPPLIED" -gt 0 ] && [ "$STD_CHECKED" -eq 0 ]; then
  if [ "$DOCS_ONLY" -eq 1 ] && [ "$EXAMINED_CHANGED" = "${#CHANGED[@]}" ]; then
    STD_ZERO_DOCS=1
    echo "   NOTE: docs-only PR — 0 of $STD_SUPPLIED standard(s) applied; accepted because every changed file is documentation and all ${#CHANGED[@]} were read, and disclosed in the comment"
  else
    die "broker checked 0 of $STD_SUPPLIED standard(s) — a clean verdict that applied none of this repo's rules is a generic review wearing this gate's badge; UNKNOWN, refusing"
  fi
fi
# 1..N-1 is a real but tolerable gap: reported, not refused.
if [ "$VERDICT" = "pass" ] && [ "$STD_CHECKED" -lt "$STD_SUPPLIED" ]; then
  echo "   NOTE: $STD_CHECKED of $STD_SUPPLIED standard(s) were checked — the verdict does not cover the rest"
fi

# The ratio is ENFORCED here, not merely printed. It used to be printed and nothing
# else: the broker only rejects files_examined=0, forge-pr parses the ratio but decides
# on the verdict word alone (its decide() never reads it), so a model that opened one
# file out of twelve and found nothing produced a PASS that unlocked a merge — the whole
# gate satisfied by 1/12 of a review (Codex [P1], 2026-08-29).
#
# Shape is allowlisted, not spot-checked: anything that is not a run of digits — "null"
# from a field the broker omitted, an empty capture, a float, a negative — is UNKNOWN,
# because `[ x -lt y ]` on a non-integer is a syntax error that `set -e` would turn into
# a bare exit nobody can read as a gate refusal.
require_count "$EXAMINED" files_examined "the size of the review is UNKNOWN, never clean"
require_count "$SUBMITTED" files_supplied_total "the size of the review is UNKNOWN, never clean"
# Same allowlist, and it is also this client's version check on the broker. A broker older
# than review-verdict@2 does not send the field at all, so jq yields "null" and the gate
# refuses. That is deliberate: the alternative is falling back to files_examined, which
# silently restores the weaker check below and leaves an un-redeployed service looking
# like a working gate. The message names the cause so the refusal is actionable.
require_count "$EXAMINED_CHANGED" files_examined_changed "a broker older than review-verdict@2 does not send this field, so redeploy review-broker.py. This gate will not fall back to files_examined, because that is the weaker check this one replaced"
# What counts as "enough examined" is the CHANGED file count, not the supplied total.
# files_examined counts changed files AND blast-radius files together (review-broker.py
# states this in the prompt), and the context files are supporting material the model is
# not obliged to open — it read 3 of 10 on this gate's own PR #48, being the 3 changed
# files and none of the 7 dependents. Demanding examined == supplied therefore fails
# essentially every PR that has a blast radius at all, and a gate that always fails is
# one that gets routed around, which is worse than the defect it was meant to close.
#
# So the rule is: every CHANGED file must have been read, because those are the subject
# of the review — and it is now checked against a count that can actually express that.
# files_examined could not. It sums the changed files AND the blast-radius files, so
# "examined >= changed" was satisfied by 2 changed files plus 1 dependent while one of the
# changed files went unread: NECESSARY, but not sufficient. review-broker.py now also
# reports files_examined_changed, counting the changed files alone (review-verdict@2). It
# obtains it by asking the model WHICH changed files it read and counting the paths that
# are genuinely in the changed set, so that count cannot exceed the changed-file total and
# no honest pair of counts clears the check below while a changed file was skipped.
#
# "Sufficient" is about the ARITHMETIC ONLY. Both numbers remain the model's self-report:
# it says how many changed files it read and nothing here proves it read them. What is
# closed is the gap where a truthful total concealed an untouched changed file; a model
# that simply lies still passes. Do not let any comment, doc or tool description upgrade
# this into verification.
#
# Only a merge-eligible verdict is gated. forge-pr treats PASS as safe to merge and
# blocks on every other word, so a partial "concerns"/"fail" already stops at the same
# place while its findings stay readable in the posted comment; killing those would cost
# the human the review without buying any safety. Same reason the broker reports this
# shortfall instead of turning it into verdict "error": an error verdict dies above,
# before section 6 posts anything, and destroys findings the human should still see.
if [ "$VERDICT" = "pass" ] && [ "$EXAMINED_CHANGED" -lt "${#CHANGED[@]}" ]; then
  die "model read $EXAMINED_CHANGED of the ${#CHANGED[@]} CHANGED file(s) — a clean verdict on a partial examination is UNKNOWN, not a pass"
fi
# The two counts must also agree with each other. The broker bounds
# files_examined_changed by the CHANGED-file count alone and deliberately does not
# reconcile it against files_examined, precisely so this check has something to catch: the
# two turns are independent self-reports and can disagree. A changed-file count above the
# total is evidence about neither number, and reconciling it upstream would have meant
# reporting a count the model never gave while leaving this guard unable to fire.
if [ "$VERDICT" = "pass" ] && [ "$EXAMINED_CHANGED" -gt "$EXAMINED" ]; then
  die "broker reported files_examined_changed=$EXAMINED_CHANGED against files_examined=$EXAMINED — the changed-file count cannot exceed the total, so the two contradict each other and neither is evidence of coverage"
fi
# Each count is also bounded by what it counts. The broker clamps both before emitting
# them, so a PASS above either bound came from something other than this broker's
# arithmetic: a stale or faulty broker, or schema drift. The checks above only ever
# compared the counts with EACH OTHER and with a floor. So 2 examined of 1 supplied, with
# 2 of 1 changed read and both overcount flags false, cleared all of them and rendered an
# unqualified all-clear (Codex [P2] on claude-memory #50; the fork this was vendored into
# had kept the bound, and upstream had not). Impossible ratios are one input-validation
# class, alongside the standards ratio above.
if [ "$VERDICT" = "pass" ] && [ "$EXAMINED" -gt "$SUBMITTED" ]; then
  die "broker reports $EXAMINED file(s) examined of $SUBMITTED supplied — an impossible ratio means the response cannot be trusted as coverage evidence; UNKNOWN, refusing"
fi
if [ "$VERDICT" = "pass" ] && [ "$EXAMINED_CHANGED" -gt "${#CHANGED[@]}" ]; then
  die "broker reports $EXAMINED_CHANGED changed file(s) read of the ${#CHANGED[@]} this PR changes — an impossible ratio; UNKNOWN, refusing"
fi
# The count above can also be wrong in the direction the comparison cannot see.
# review-broker.py CLAMPS files_examined down to files_supplied_total when the model
# claims more files than it was handed, and records that in examined_overcounted ("a
# count larger than what was supplied is not a bigger review, it is an unreliable
# self-report"). The clamped value is therefore >= the changed-file count by
# construction, the check above passes, and a PASS goes out on a number the broker had
# just declared untrustworthy — a model that hallucinates reading fifty files when given
# ten reads as full coverage. Codex [P1] on PR #49.
#
# Only a literal false clears it: absent or unparseable means this client cannot tell
# whether the number was clamped, and cannot-tell is UNKNOWN. Gated on a merge-eligible
# verdict only, for the same reason the check above is — a partial concerns/fail already
# stops at forge-pr, and killing it here would cost the human its findings.
# Read with its JSON TYPE, not through jq -r alone. jq -r prints the string "false" and
# the boolean false identically, so a broker emitting the wrong type cleared a check that
# means "the literal boolean false" (Codex [P2] on claude-memory #50). Anything that is
# not a boolean becomes a value no case arm below accepts.
OVERCOUNTED=$(jq -r '.examined_overcounted | if type == "boolean" then tostring else "non-boolean \(type) \(tojson)" end' "$V")
case "$OVERCOUNTED" in
  false) : ;;
  # REPORTED, not fatal — downgraded once files_examined_changed existed. When this
  # guard was written the AGGREGATE count was the only coverage signal there was, so a
  # clamped overcount destroyed the evidence entirely and refusing was right. It is no
  # longer the only signal: the changed-scoped count below is checked separately and
  # carries its own overcount flag, which stays fatal. What is left here is a model that
  # cannot count, and the clamp already bounds its claim to the true supplied total —
  # the error direction is "read MORE than I was given", never less.
  #
  # Measured before downgrading: 14 of 613 cached verdicts (2%) carry this flag, and the
  # cache key includes the request, so a PR that trips it stays blocked until someone
  # pushes an empty commit to force a re-judge. Hard-failing 2% of PRs on the model's
  # arithmetic, with recovery only by fabricating a commit, is not proportionate to a
  # signal that is now redundant. Live example: geekspace PR #23, blocked on
  # "examined 3/3" with the model claiming more.
  true)  echo "   NOTE: broker clamped an overcounted files_examined to $EXAMINED — the aggregate self-report is unusable; coverage rests on the changed-file count checked below" ;;
  # ABSENT stays fatal. That is schema drift between two processes with no shared
  # contract, not a model miscount, and it is the case where this client genuinely
  # cannot tell what it is looking at.
  # ABSENT stays fatal, but ONLY on a merge-eligible verdict. Rewriting this check as a
  # case dropped the "$VERDICT" = pass guard the previous `if` carried, which made schema
  # drift kill a concerns/fail run before section 6 could post its findings — discarding
  # actionable review output to prevent a merge that a non-pass verdict already prevents
  # at forge-pr. That is the same trade the two checks above refuse to make (Codex [P2]).
  *)
    if [ "$VERDICT" = "pass" ]; then
      die "broker did not report examined_overcounted (got '$OVERCOUNTED') — this gate cannot confirm $EXAMINED was not a clamped overcount, and an unconfirmable count is UNKNOWN, not a pass"
    fi
    echo "   NOTE: broker did not report examined_overcounted (got '$OVERCOUNTED') — coverage is unconfirmable, but the '$VERDICT' verdict already blocks the merge, so the findings are posted rather than discarded"
    ;;
esac
# The changed-file count is clamped by the same broker for the same reason, so it carries
# the same blind spot and needs the same flag. A model claiming it read 9 of 3 changed
# files is pinned to 3, which then clears the "read every changed file" check above on a
# number the broker had just declared unreliable. Written as a second block rather than
# folded into the one above: the two are independently reviewable, and the wording differs
# because the bound differs (supplied total vs changed-file count).
#
# Only a literal false clears it, for the reason given above — absent means this client
# cannot tell whether the number was clamped, and cannot-tell is UNKNOWN.
# Type-preserving, for the reason given at OVERCOUNTED above.
CHANGED_OVERCOUNTED=$(jq -r '.examined_changed_overcounted | if type == "boolean" then tostring else "non-boolean \(type) \(tojson)" end' "$V")
if [ "$VERDICT" = "pass" ] && [ "$CHANGED_OVERCOUNTED" != "false" ]; then
  if [ "$CHANGED_OVERCOUNTED" = "true" ]; then
    die "broker clamped an overcounted files_examined_changed to $EXAMINED_CHANGED — the model claimed to read more changed files than the PR contains, so the count is not evidence of coverage and a clean verdict on it is UNKNOWN, not a pass"
  fi
  die "broker did not report examined_changed_overcounted (got '$CHANGED_OVERCOUNTED') — this gate cannot confirm $EXAMINED_CHANGED was not a clamped overcount, and an unconfirmable count is UNKNOWN, not a pass"
fi
# An unread supplied file is a real degradation, just not a failing one. Say so on the
# console rather than letting "$EXAMINED/$SUBMITTED" above pass for a full read; the
# same ratio is rendered into the posted comment, where forge-pr and a human both see it.
#
# Reports the changed-file count instead of asserting "the changed files were covered".
# That claim held only for a PASS -- the guards above are gated on one -- so on a
# concerns/fail run where a CHANGED file went unread the console said the opposite of
# what happened. Same defect as the posted comment's blast-radius wording (Codex [P2] on
# PR #67), one level up; fixed here too rather than left because only the other one was
# named.
if [ "$EXAMINED" -lt "$SUBMITTED" ]; then
  echo "   NOTE: $(( SUBMITTED - EXAMINED )) of $SUBMITTED supplied file(s) went unread ($EXAMINED_CHANGED/${#CHANGED[@]} changed file(s) read)"
fi

# ---- 6. post it back --------------------------------------------------------------
# --argjson for the changed count so it renders as a bare number, not a quoted string.
# The "N/M supplied file(s) examined" segment must keep its exact wording and position:
# forge-pr parses it with VERDICT_META_RE, and a comment whose meta line stops matching
# makes forge-pr raise rather than merge. The changed-file segment is therefore appended
# AFTER it, never inserted before.
#
# The zero-findings sentence is COVERAGE-AWARE, and the coverage note below exists,
# because the flat sentence made a claim the review had not earned: "No findings in the
# changed code or its blast radius" went out on PR #58 at 2/10 examined, where zero of the
# 8 blast-radius files were opened. The numbers in the meta line were correct and the
# prose beside them contradicted them — the same "reviewed less than it claimed" shape as
# the truncation and partial-examination defects above, arriving in the one artifact a
# human actually reads. The honest line existed only as an `echo` to the CI console
# (section 5's NOTE), which nobody reads on a green run.
#
# The note renders for EVERY verdict, not just a clean one: "2 findings" beside "8 of 10
# unread" is exactly as material to a reader as "no findings" beside it. It asserts only
# the two counts and never which files were skipped — the changed-file guard above holds
# for a PASS only, so on a concerns/fail comment "the unread ones were all context" would
# be an inference this script cannot make.
#
# REPORTS THE TWO RATIOS AS GIVEN, and derives nothing. Written against the whole
# value-shape domain rather than the case that prompted it, because the two shortfalls
# are independent and the first two attempts each fixed one cell and broke another
# (Codex [P2] on PR #67, three rounds). With A = supplied - examined and
# B = changed - examined_changed:
#   A=0 B=0  no note.
#   A>0 B=0  aggregate short; changed files complete.
#   A=0 B>0  the two self-reports CONTRADICT each other -- changed files are a subset of
#            supplied, so "read every supplied file" and "missed a changed file" cannot
#            both hold. Permitted here: the coherence guard above catches only
#            examined_changed > examined, and it is gated on a PASS besides. Rendering
#            "0 of 3 supplied file(s) went unread" was the contradiction that killed the
#            subtraction form.
#   A>0 B>0  both short.
# A derived difference is false or absurd in two of those four; the raw pair is true in
# all four, including the incoherent one, and the reader can see the disagreement. The
# closing sentence says "only what was read" for the same reason -- "not every supplied
# file" contradicts examined == supplied in the third row.
#
# Keyed on EITHER shortfall, never the aggregate alone. files_examined == supplied with
# files_examined_changed < changed is a combination the broker and this script deliberately
# permit on a concerns/fail verdict (the changed-file guards above are gated on a PASS), and
# keying only on the aggregate suppressed the warning exactly there -- a comment reading
# "3/3 supplied file(s) examined" with no note while a CHANGED file went unread. That is the
# aggregate-vs-changed lesson this gate already learned once, arriving in the prose layer
# (Codex [P2] on PR #67, second round). The sentence reads from the same condition so both
# follow one rule instead of a chain of assumptions about which verdicts carry zero findings.
#
# Hence "not every supplied file" and NOT "not the whole blast radius". The blast-radius
# wording was this fix's own version of the overclaim it was written to remove: on a
# concerns/fail verdict the shortfall can be a CHANGED file (2/3 examined, 1/2 changed
# read is reachable and permitted), and naming the blast radius there points the reader
# away from unreviewed changed code (Codex [P2] on PR #67). The counts say which; the
# prose must not guess.
#
# It cannot be mistaken for a finding by forge-pr: FINDING_RE anchors on "### " plus a
# severity emoji, and this line is a blockquote. Verified against the deployed parser.
BODY=$(jq -r --arg sha "${HEAD_SHA:0:8}" --arg br "$BR_COUNT" --arg scanned "$BR_SCANNED" \
  --arg generated "$GENERATED_NOTE" \
  --argjson changed "${#CHANGED[@]}" --argjson skipped "$CTX_SKIPPED" \
  --argjson truncated "$CTX_TRUNCATED" --argjson omitted "$CTX_OMITTED" \
  --argjson unreadable "$BR_UNREADABLE" --argjson stdzerodocs "$STD_ZERO_DOCS" \
  --argjson ctxcap "$CONTEXT_CAP" '
  "## 🤖 Local AI review — **" + (.verdict|ascii_upcase) + "**\n\n" +
  "`" + $sha + "` · model `" + .model + "` · " +
  (.files_examined|tostring) + "/" + (.files_supplied_total|tostring) + " supplied file(s) examined" +
  (if .examined_overcounted == true then " ⚠️ (clamped — unreliable)"
   elif .examined_overcounted != false then " ⚠️ (unconfirmed)"
   else "" end) + " · " +
  (.files_examined_changed|tostring) + "/" + ($changed|tostring) + " changed file(s) read · " +
  $br + " dependent(s) from " + $scanned + " scanned · " +
  (.standards_checked|tostring) + "/" + (.standards_supplied|tostring) + " project standards checked" +
  (if .cached then " · _cached verdict_" else "" end) + "\n\n" +
  # Placed AFTER the metadata line terminates, not inside it. Injected mid-line it landed
  # between "supplied file(s) examined · " and the changed-file ratio, splitting the
  # metadata in half and putting the "> " marker somewhere other than the start of a
  # line, where Forgejo renders it as literal text rather than a blockquote (Codex [P2]
  # on PR #71, fourth round). Disclosed on EVERY verdict: the $skipped term further down
  # guards only the "no findings ... or its blast radius" sentence, which a verdict with
  # findings never reaches.
   (if $skipped > 0 then
      "> ⚠️ " + ($skipped|tostring) + " dependent(s) were refused as non-regular or " +
      "unreadable and never sent to the model, so this blast radius is **incomplete**. " +
      "The changed files are unaffected.\n\n"
    else "" end) +
  # Files the RESOLVER could not search, one step upstream of the refusal above: they
  # were never candidates, so no dependent count reflects them. Same placement and same
  # every-verdict rule. Unknown (-1) gets its own wording rather than a made-up number.
   (if $unreadable > 0 then
      "> ⚠️ " + ($unreadable|tostring) + " tracked file(s) could not be read by the " +
      "blast-radius resolver (over its size limit or not text) and were never searched " +
      "for references to this change, so this blast radius is **incomplete**. The " +
      "changed files are unaffected.\n\n"
    elif $unreadable < 0 then
      "> ⚠️ The blast-radius resolver did not report which files it could not read, so " +
      "this blast radius is **unverified**. The changed files are unaffected.\n\n"
    else "" end) +
  # The two cuts made by the context budget, disclosed beside the refusal above and for the same
  # reason: files_examined counts what was SENT, so neither cut can show up as a
  # shortfall in the ratio. Blockquote below the metadata line, so forge-pr (header,
  # metadata and "### " finding lines only) reads the comment exactly as before.
   (if ($truncated > 0) or ($omitted > 0) then
      "> ⚠️ Context budget: " +
      ([ (if $truncated > 0 then ($truncated|tostring) + " dependent(s) were sent " +
            "truncated to their first " + ($ctxcap|tostring) + " bytes" else empty end),
         (if $omitted > 0 then ($omitted|tostring) + " dependent(s) were omitted by " +
            "the context-file limit and never sent" else empty end) ] | join("; ")) +
      ". This blast radius is **partial**. The changed files are unaffected.\n\n"
    else "" end) +
  # The docs-only exceptions, disclosed where the reader looks. Both are on the record in
  # the verdict (files_examined_reported, files_examined_source); this puts them in the
  # comment, so the pass on a docs PR never reads as a rule check that did not happen.
   (if .files_examined_source == "follow-up" then
      "> ℹ️ Docs-only: the review turn reported 0 files examined (it counts files containing code), " +
      "so the examined count above is its follow-up answer, which named every changed " +
      "file as read.\n\n"
    else "" end) +
   (if $stdzerodocs == 1 then
      "> ℹ️ Docs-only: **no project standard was applied**. This PR changes only " +
      "documentation, and the model judged none of the " +
      (.standards_supplied|tostring) + " standards applicable. This pass means the " +
      "text was read and nothing was flagged. It is not a rule check.\n\n"
    else "" end) +
  # The console NOTE is ephemeral; THIS is the artifact a human and forge-pr actually
  # read. Without it the comment presents a clamped N/N as full coverage, and the
  # unread-context warning cannot fire either because the clamp made the numbers equal —
  # the durable record would state more than the gate knows (Codex [P2]).
  # Both untrustworthy shapes get the caveat, not just the clamp. An ABSENT flag reaches
  # this point only on a non-pass verdict (a PASS dies upstream), and that path continues
  # ON PURPOSE so the findings survive -- but continuing while the comment renders an
  # ordinary N/N would hand the reader a coverage claim nothing verified. Same principle
  # as the clamp case, same gap otherwise (Codex [P2]).
  (if .examined_overcounted == true then
     "> ⚠️ The model reported reading more files than it was supplied, so the broker " +
     "clamped the aggregate count above and it is **not** evidence of coverage. The " +
     "changed-file count beside it is validated separately and is what this verdict " +
     "rests on.\n\n"
   elif .examined_overcounted != false then
     "> ⚠️ The broker did not report whether the aggregate count above was clamped, so " +
     "this gate could not confirm it. The findings below stand; the coverage ratio does " +
     "not.\n\n"
   else "" end) +
  # The blast-radius claim also drops when the aggregate count is UNTRUSTWORTHY, not only
  # when it is short, and this term is LIVE rather than defensive. A clamped count is no
  # longer fatal on a PASS -- section 5 downgraded it to a console NOTE and continues --
  # so "pass, zero findings, examined_overcounted=true" now reaches this template, with
  # examined == supplied because the clamp made them equal. Both shortfall terms are
  # therefore false, and without this one the sentence would claim a clean blast radius
  # directly beneath the caveat above saying that same count is not evidence of coverage.
  # Merging the two warnings without it reintroduces the overclaim both exist to remove,
  # on a third axis. `!= false` is the allowlist the guards upstream use: absent is
  # untrustworthy, not trustworthy (absent is still fatal on a PASS, so only `true`
  # reaches here with zero findings -- the broker maps zero findings to `pass`).
  (if (.findings|length) == 0 then
     (if (.files_examined < .files_supplied_total)
         or (.files_examined_changed < $changed)
         or (.examined_overcounted != false)
         or ($skipped > 0)
         or ($truncated > 0)
         or ($omitted > 0)
         or ($unreadable != 0)
      then "No findings in the changed code.\n"
      else "No findings in the changed code or its blast radius.\n" end)
   else ((.findings | map(
     "### " + (if .severity=="critical" then "🔴" elif .severity=="major" then "🟠" else "🟡" end) +
     " " + .severity + " — " + .category + "\n" +
     "**" + .file + (if .line then ":" + (.line|tostring) else "" end) + "** — " + .summary + "\n\n" +
     .why + "\n") | join("\n"))) end) +
  (if (.files_examined < .files_supplied_total)
      or (.files_examined_changed < $changed) then
     "\n> ⚠ **Reduced coverage** — read " + (.files_examined|tostring) + " of " +
     (.files_supplied_total|tostring) + " supplied file(s), " +
     (.files_examined_changed|tostring) + " of " + ($changed|tostring) +
     " changed file(s). Findings above cover only what was read.\n"
   else "" end) +
  (if $generated == "" then "" else
     "\n> **Generated artifacts excluded from this review** — compiled output whose typed\n" +
     "> source IS under review in this PR. Listed so the coverage claim above is read\n" +
     "> correctly: these bytes were never sent to the model.\n>\n" +
     ($generated | split("\n") | map(select(. != "")) | map("> " + .) | join("\n")) + "\n"
   end) +
  "\n---\n_Advisory only — this gate does not block merges. Reviews the change and the " +
  "files that depend on it, not the whole project._"' "$V")

if [ "$POST" -eq 1 ]; then
  FHDR=$(mktemp); CMT=$(mktemp)
  trap 'rm -f "$REQ" "$DTMP" "$CJSON" "$V" "$BHDR" "$FHDR" "$CMT"' EXIT
  printf 'Authorization: token %s\n' "$FT" > "$FHDR"
  # The body goes through a file too. Not a credential, but a long review on argv is
  # an E2BIG waiting for the PR that finally exceeds the limit.
  jq -n --arg b "$BODY" '{body:$b}' > "$CMT"
  # Bounded, like the broker call. Without -m a forge that accepts the connection and
  # then stalls holds this POST open until the CI job's own timeout cancels it, with the
  # review finished and never published (Codex [P2] on claude-memory #50: the fork there
  # carried -m 60, and upstream never had it). A curl failure inside $( ) would also have
  # ended the script under set -e with curl's bare exit code and no message, hence the die.
  pc=$(curl -sS -m "$FORGE_POST_TIMEOUT" -o /dev/null -w '%{http_code}' -X POST \
       -H @"$FHDR" -H 'Content-Type: application/json' \
       --data-binary @"$CMT" \
       "$FORGE_API/repos/$REPO/issues/$PR/comments") \
    || die "the forge did not accept the review comment within ${FORGE_POST_TIMEOUT}s (curl exit $?) — the review ran but nobody will see it"
  [ "$pc" = "201" ] || die "could not post the review comment (HTTP $pc) — the review ran but nobody will see it"
  echo "   posted to $REPO PR #$PR"
else
  echo "$BODY"
fi

# Advisory: a real verdict, even "fail", is a successful RUN of the gate.
exit 0
