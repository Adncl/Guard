# Research log

## 2026-09-19 — Mosquitto MQTT 5.0 case started

The second paper case was identified as Mosquitto revision `849e0f`, rather
than relabeling the Sol MQTT 3.1.1 implementation. The exact source archive is
stored under `output/vendor/`, with a source and build manifest.

The baseline and GLLVM builds completed with Clang/LLVM 14. SVF-2.9 Andersen
whole-program analysis completed and produced `output/mosquitto-ir/ffp.txt`.
The analyzer produced 479 functions, 69,601 IR nodes, and 170,433 edges, and
records the SVF method in the analysis metadata.

The dynamic adapter was smoke-tested with an independently serialized MQTT 5.0
CONNECT + PINGREQ control. Mosquitto returned a successful CONNACK and
PINGRESP; the positive oracle accepts implementation-defined MQTT 5 properties.

The live 118-rule LLM-guided slicing run reached rule 68/118 before the
configured DeepSeek endpoint returned HTTP 402 (insufficient credit). The
first 67 rules retain live/cache-backed slicing observations; the remaining
51 rules were filled by an explicitly labelled conservative offline resume so
the static database has all 118 rows. A cached-only detection pass records 118
inconclusive results and makes no compliance claim. The live observations are
exported to `output/mosquitto-llm-cache-export.json` before that overwrite.

Independent MQTT 5 wire replay is recorded in
`output/mosquitto-manual-cases.json`. The positive CONNECT + PINGREQ control
returned CONNACK Success and PINGRESP. Malformed ShareName and zero
Subscription Identifier probes were rejected with DISCONNECT 0x81. A distinct
overlapping-filter QoS 2 probe produced two outgoing publications with QoS
`[2, 0]` (one at the requested maximum and one lower-QoS duplicate), which is
wire-level evidence relevant to the paper's overlapping-subscription finding.
The Topic Alias probe did not create a server-to-client publication and is
therefore inconclusive. No assertion-generated/instrumented dynamic result or
fuzzing result is claimed while the LLM credit blocker remains.

## 2026-09-19 — Full live slicing resumed

After the user reported that credit was restored, the exact
`run_mosquitto.sh slice` MatchPass entry was rerun. All 118 per-rule records
now carry `live-LLM` slicing provenance; the previous offline-resume records
were replaced.

The live detection stage completed rules 1–7, all self-consistent `no violation
found!`. At rule 8, the DeepSeek reasoning endpoint returned HTTP 402 again;
a retry failed immediately at the same point. The database contains seven
live detection results, sixty older inconclusive checkpoints, and fifty-one
rules without a detection result. Assertion generation and fuzzing remain
deferred until detection is complete.

The live slice stage was then rerun once more after tightening checkpoint
invalidation: every live slice now clears any prior detection JSON, even when
its text is unchanged. The current database consequently has 118 clean live
slices and zero detection rows, ready for a credit-available resume. The 34
completed detection cache entries remain exported for audit, but are not
treated as current results until the clean run reaches self-consistency.
