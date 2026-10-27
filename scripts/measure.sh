#!/usr/bin/env bash
# Reproduces every number in the README on the current host.
#
#   scripts/measure.sh [OUT_DIR]
#
# Needs: release build of the workspace (cargo build --release --locked),
# the eBPF object (cd toolprof-ebpf && cargo build --release, or
# TOOLPROF_EBPF_OBJ=<path>), and sudo for the trace steps only.
# Enforcement and measurement run unprivileged.
# Exits non-zero if an acceptance criterion is not met.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/out}"
BIN="$ROOT/target/release"
CASES="$ROOT/calc-tool/cases.tsv"
OBJ=()
if [[ -n "${TOOLPROF_EBPF_OBJ:-}" ]]; then OBJ=(--object "$TOOLPROF_EBPF_OBJ"); fi
mkdir -p "$OUT"

tp() { "$BIN/toolprof" "$@"; }
confined() { echo "$BIN/toolprof" run -p "$1" -- "$BIN/calc-tool"; }

echo "== kernel: $(uname -r)"

echo "== 1. trace the suite (sudo, eBPF)"
sudo -E "$BIN/toolprof" trace "${OBJ[@]}" -c calc-tool -o "$OUT/trace.jsonl" -- \
  "$BIN/calc-suite" --cases "$CASES" -- "$BIN/calc-tool"

echo "== 2. synthesize"
tp synth -i "$OUT/trace.jsonl" -c calc-tool -o "$OUT/profile.json" --report "$OUT/report.json"

echo "== 3. offline gate: trace vs its profile"
tp diff -c calc-tool -p "$OUT/profile.json" -i "$OUT/trace.jsonl" | tail -n 1

echo "== 4. enforce: suite under the profile (criterion: 0 blocks)"
"$BIN/calc-suite" --cases "$CASES" -- $(confined "$OUT/profile.json") | tee "$OUT/suite-confined.json"

echo "== 5. probes outside the profile (each must be stopped)"
: > "$OUT/probes.txt"
for p in open-file create-file mmap-exec write-stderr socket spawn; do
  set +e
  r="$(tp run -p "$OUT/profile.json" -- "$BIN/calc-tool" --probe "$p" 2>/dev/null)"
  st=$?
  set -e
  if [[ $st -eq 159 ]]; then r="SIGSYS"; fi
  echo "$p: $r" | tee -a "$OUT/probes.txt"
  if [[ "$r" == *'"escaped":true'* ]]; then echo "probe $p escaped" >&2; exit 1; fi
done

echo "== 6. attack surface (criterion: >= 80% vs Docker default)"
tp surface -p "$OUT/profile.json" --docker "$ROOT/data/docker-default.json" \
  --baseline mcp-server-rs="$ROOT/data/baseline-mcp-server-rs.json"
tp surface -p "$OUT/profile.json" --docker "$ROOT/data/docker-default.json" \
  --baseline mcp-server-rs="$ROOT/data/baseline-mcp-server-rs.json" --json > "$OUT/surface.json"

echo "== 7. held out: profile from cases 0,2,4..., enforced on 1,3,5..."
sudo -E "$BIN/toolprof" trace "${OBJ[@]}" -c calc-tool -o "$OUT/trace-half.jsonl" -- \
  "$BIN/calc-suite" --cases "$CASES" --part 0/2 -- "$BIN/calc-tool"
tp synth -i "$OUT/trace-half.jsonl" -c calc-tool -o "$OUT/profile-half.json"
set +e
"$BIN/calc-suite" --cases "$CASES" --part 1/2 -- $(confined "$OUT/profile-half.json") | tee "$OUT/suite-heldout.json"
set -e

echo "== 8. fuzzing under the full profile (1000 inputs, seed 1; reported, not a gate)"
set +e
"$BIN/calc-suite" --fuzz 1000 --seed 1 -- $(confined "$OUT/profile.json") | tee "$OUT/suite-fuzz.json"
set -e

python3 - "$OUT" <<'PY'
import json, sys
out = sys.argv[1]
s = json.load(open(f"{out}/surface.json"))
d = s["reductions"][0]
c = json.load(open(f"{out}/suite-confined.json"))
summary = {
    "syscalls": s["profile"]["syscalls"],
    "conditioned": s["profile"]["conditioned"],
    "docker_syscalls": d["baseline_syscalls"],
    "reduction_syscalls": round(d["syscalls"], 4),
    "reduction_weighted": round(d["weighted"], 4),
    "reduction_weighted_conservative": round(d["weighted_conservative"], 4),
    "suite": f'{c["passed"]}/{c["cases"]}',
    "suite_blocks": c["failed"],
    "heldout": json.load(open(f"{out}/suite-heldout.json")),
    "fuzz": json.load(open(f"{out}/suite-fuzz.json")),
}
for k in ("heldout", "fuzz"):
    summary[k] = {x: summary[k][x] for x in ("cases", "passed", "failed", "sigsys")}
json.dump(summary, open(f"{out}/measurement.json", "w"), indent=1)
print(json.dumps(summary, indent=1))
ok = d["syscalls"] >= 0.80 and d["weighted"] >= 0.80 and c["failed"] == 0
sys.exit(0 if ok else 1)
PY
