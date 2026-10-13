# Findings

## Current understanding

The paper's second MQTT case is Mosquitto MQTT 5.0 at revision `849e0f`. The
static path is protocol-independent once the target build and source metadata
are supplied; dynamic verification requires a target/protocol adapter.

## Evidence so far

- 118 exact-text-deduplicated MQTT 5.0 rules are prepared from the checked-in
  structured specification extraction artifact.
- Mosquitto baseline and GLLVM builds complete in the pinned LLVM-14 image.
- SVF-2.9 Andersen analysis runs on the Mosquitto whole-program bitcode.
- MQTT 5.0 deterministic positive replay is accepted with CONNACK Success and
  PINGRESP; MQTT 5 response properties are not hard-coded.
- The paper's four Mosquitto bug descriptions were checked against the exact
  source. ShareName `foo+` and Subscription Identifier `0` probes are rejected
  with MQTT 5 DISCONNECT reason `0x81` in this commit, so those two probes do
  not reproduce a bug. Two distinct overlapping filters, one QoS 0 and one
  QoS 2, followed by an incoming QoS 2 publication produce two outgoing
  publications with QoS `[2, 0]`; this is an independent wire discrepancy
  consistent with the overlapping-subscription finding, but it is not yet a
  ProtocolGuard assertion-trigger result.
- The full live LLM slicing stage has now completed all 118 rules. A detection
  attempt reached seven self-consistent `no violation found!` rules before the
  DeepSeek reasoning endpoint returned HTTP 402 at rule 8 on two consecutive
  attempts. After tightening checkpoint invalidation, the current database
  contains 118 clean live slices and zero current detection rows; the 34
  completed detection cache entries are retained only as audit evidence. No
  assertion or fuzzing claim is made until a clean detection run completes.

## Open questions

- Which of the 118 rules produce confirmed Mosquitto inconsistencies after the
  original LLM-guided run can be completed with available credit?
- Which generated assertions compile and which have an independent wire-level
  witness under MQTT 5.0 replay?
- How many verified seeds can trigger the bounded AFLNet smoke campaign?
