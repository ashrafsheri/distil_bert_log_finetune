# LogGuard Architecture Improvement Plan

**Context.** This plan is a repo-specific, paper-grounded redesign of the LogGuard anomaly-detection service. The system today is a multi-tenant, warmup-sensitive, real-time detector built around a shared transformer teacher, per-project distilled students, a regex rule layer, and an Isolation Forest side channel. It works well enough as a product, but as a research artifact it fails on (1) open-world template handling, (2) calibration, (3) online adaptation, and (4) evaluation rigor. The goal below is to evolve it — not rewrite it — into something that is simultaneously more useful in production and defensible at ICSE/ASE/ACSAC.

Assumptions are labelled **[A]** throughout. Code citations use `file:line` form.

---

## A. Current Architecture

### Services and flow
1. Backend (`backend/app/controllers/log_controller.py`) parses incoming logs via `backend/app/services/log_parser_service.py` (pure regex; no Drain/Spell), classifies traffic, and forwards structured batches to the anomaly service's `POST /detect/batch/structured` (`realtime_anomaly_detection/api/server_multi_tenant.py:765`).
2. The anomaly service is orchestrated by `MultiTenantDetector` (`realtime_anomaly_detection/models/multi_tenant_detector.py:52`). It owns per-project lifecycle, sessions, reservoirs, route canonicalization, and manifest-aware traffic classification.
3. Scored documents go back to the backend, which writes them to Elasticsearch (`logguard-logs`) and fans out via websockets.

### Detector lifecycle
Projects cycle through `WARMUP → TRAINING → ACTIVE`, managed by `project_manager.py`. During WARMUP all scoring is done by the shared **teacher** (`teacher_model.py:68-236`). When `baseline_eligible` events cross the per-project threshold (`multi_tenant_detector.py:1513-1574`), a **student** is trained off teacher soft labels via KD (`student_model.py:340-603`, `knowledge_distillation.py:97-190`) and the project transitions to ACTIVE.

### Model stack (literal)
- **Teacher transformer** (`teacher_model.py:264`): causal encoder, `d_model=256`, `n_heads=8`, `n_layers=4`, `ffn=1024`, `window_size=20`. Loss: next-template CE with `ignore_index=pad_id`. NLL threshold default `6.5`, recalibrated to p95 after each update (`teacher_model.py:773-797`).
- **Student transformer** (`student_model.py:203-212`): same family but `d_model=128`, `n_heads=4`, `n_layers=2`. Trained with `α·KL(student‖teacher)·T² + (1-α)·CE`, α=0.5, T=3.0 (`student_model.py:500-527`). Vocab is frozen at training time.
- **Rule layer** (`ensemble_detector.py:97-184`): hand-written regexes for SQLi / XSS / path traversal / command injection, severity weights 0.3–1.5, applied to URL-decoded path + heuristic bonuses.
- **Isolation Forest** (`teacher_model.py:137`, `student_model.py:544-575`): feature-based; student uses `contamination='auto'` with 0.05 fallback; threshold is p95 of calibration scores.
- **Ensemble vote** (`teacher_model.py:575-601`, `student_model.py:795-822`): weighted majority over `(rule_weight, iso=0.5, transformer=0.7)`; anomaly iff `ensemble_score > 0.5`.

### Open-world / cold-start behaviour
- Unknown tokens collapse to a single `unknown_id` (`teacher_model.py:397-400`).
- If unknown-template ratio of a sequence ≥ 0.5, the transformer short-circuits and emits a "penalty" anomaly score `ratio·threshold` (`teacher_model.py:521-533`). `MAX_UNKNOWN_TEMPLATE_RATIO` is hardcoded.
- Endpoint manifest seeding (`multi_tenant_detector.py:_match_endpoint_manifest`, external `scripts/extract_api_manifest.py`) pre-populates "known" templates so scanners of unknown routes are flagged as `internal_probe` / anomalous rather than drowning the warmup set.
- Route canonicalization (`multi_tenant_detector.py:_canonicalize_path`) strips UUIDs / tokens / numeric IDs.

### Reservoirs and online updates
Each student keeps three reservoirs (`student_model.py:125-127`): `clean_normal` (2048), `suspicious` (1024), `confirmed_malicious` (1024), populated post-detection (`multi_tenant_detector.py:1096`). The global `TeacherUpdateScheduler` (`knowledge_distillation.py:416-572`) sweeps them every ~7 days to refit the teacher transformer (2 epochs, lr 1e-5) and Isolation Forest. **Students themselves are never retrained after initial fit** — that is the single biggest behavioural surprise in the code.

### Evaluation harness
`scripts/backtest_harness.py` replays sorted events through `MultiTenantDetector.detect_structured`, computes TP/FP/TN/FN + incident-level F1 (`:389-457`). There is no PR-AUC, no ROC-AUC, no threshold sweep, no calibration error, no latency histogram, no online-update eval, no cross-system transfer, no baseline. `train_openstack.yaml` declares f1/pr-auc/roc-auc targets that no code ever computes.

### Strengths and current bets worth keeping
1. **Manifest-aware baseline eligibility** is the best single idea in the repo. It makes the warmup distribution intentional instead of incidental. Most papers ignore this entirely.
2. **Traffic classes + baseline_eligible flag** (`multi_tenant_detector.py:1184-1202`) cleanly separate "what to learn from" from "what to score" — a cleaner abstraction than most HDFS-era baselines.
3. **Student = small distilled project-local model** is directionally right and matches `LogMoE` / `CollaborLog`.
4. **Causal next-template LM + NLL threshold** is a defensible teacher design, directly comparable to `DeepLog` / `LogBERT`.
5. **Hybrid rule + ML** is operationally essential for web logs and the right call (cf. Locate-Then-Detect, Detecting Web Attacks with E2E DL).

---

## B. Literature-to-Repo Gap Matrix

| # | Paper | Core idea | Why it matters | In repo? | Where / gap | Recommended action |
|---|---|---|---|---|---|---|
| 1 | **DeepLog** | LSTM next-event language model + top-k deviation threshold | Baseline formulation of "sequence LM as anomaly detector" | **Yes** (conceptually) | `teacher_model.py:535-554` uses NLL, not top-k, on a transformer | Add a top-k deviation fallback mode for ablation; keep transformer. |
| 2 | **LogAnomaly** | Template2Vec (synonym/antonym) + count+sequence hybrid | Token semantics beat integer IDs on unstable logs | **No** | Templates are integer IDs (`teacher_model.py:397-400`). `ApacheLogNormalizer` is lexical only (`ensemble_detector.py:191-257`) | Replace integer template vocab with a frozen sentence-piece / MiniLM embedding of the *template text*; treat new templates as nearest-neighbour in embedding space. Biggest single gain for open-world. |
| 3 | **LogBERT** | Masked-log-model pretraining + deviation from hypersphere center | Semi-supervised pretraining without labels | **Partial** | `train_hdfs.yaml` declares an MLM pretrain but no runtime path uses it as the teacher; the live teacher is causal CE | Wire the HDFS/LogBERT-MLM checkpoint as the teacher *encoder* and keep a lightweight causal head; gives you a real pretrained base. |
| 4 | **HitAnomaly** | Hierarchical transformer: token → template → sequence | Handles long bursty sessions without flattening structure | **No** | Everything is flattened into a 20-token window (`teacher_model.py:264`) | Adopt a two-level encoder (template-content encoder + session encoder). Matches the "session + request" structure you already have. |
| 5 | **Robust Log AD (Zhang et al.)** | Attention + FastText semantics tolerant of template drift | Survives unstable logs in production | **No** | Unknown templates collapse to `unknown_id`; no drift tolerance | Combine with #2: semantic embeddings make drift a continuous distance instead of a cliff. |
| 6 | **LogTransfer** | Cross-system transfer via shared encoder + per-system head | Reuse knowledge across tenants/systems | **Partial** | Teacher→student KD is *within* a shared vocabulary universe, not cross-system transfer | Treat each tenant as a "system": shared semantic encoder, per-tenant light head. Your multi-tenant setup is *already* shaped like this. |
| 7 | **MetaLog** | MAML-style meta-learning for fast adaptation to new systems with few labels | Exactly the "new tenant cold-start" problem | **No** | Cold-start is fully unsupervised + warmup-based | **Strongest paper-novelty bet.** Meta-train across existing tenants so a new tenant needs only N≪current warmup to reach ACTIVE. |
| 8 | **LogOnline** | Semi-supervised online learning with PU-style positive unlabelled reservoir | Students should *keep learning* after go-live | **No** | Students are frozen after first fit (`student_model.py:587-589`). Reservoirs exist but only feed the teacher weekly | Wire an online student-update path using your existing `clean_normal_reservoir`; this is low-risk and directly addresses a documented weakness. |
| 9 | **LogOW** | Open-world detection with "novelty class" head + rejection option | Distinguish "unknown" from "anomalous" | **No** | Unknown ratio collapses to an anomaly penalty regardless of intent (`teacher_model.py:521-533`) | Split the decision into `novel | benign | malicious` with a rejection class fed into calibration. |
| 10 | **LogMoE** | Lightweight expert mixture, gate routes per tenant/system | Efficient cross-system specialization | **Partial** | One student per project is effectively one expert per tenant, but there is no gating network over a *shared* expert pool | Replace "one student per project" with "one small expert per cluster of tenants + gate". Lower cold-start cost, better small-tenant quality. |
| 11 | **CollaborLog** | Large/small model collaboration: big model escalated on uncertain cases | Latency/quality tradeoff in evolving software | **Partial** | Teacher + student split is the same shape, but teacher is *not* escalated by uncertainty — it's only used during warmup | Use the teacher as a **runtime escalation path** when student confidence is low (e.g. entropy above threshold or unknown-ratio in gray zone). Free big quality win. |
| 12 | **OneLog** | End-to-end char/BPE model, no parser | Avoid parser brittleness entirely | **No** | Parser + template vocab is on the critical path | Not worth full adoption — parser fits your rule layer. But take the char-BPE fallback for *unparseable* lines instead of dropping them. |
| 13 | **Impact of log parsing on DL AD (He et al.)** | Parser choice dominates downstream F1; Drain > regex | Your regex parser is the weakest link | **No** | `log_parser_service.py` is handwritten regex | Adopt **Drain3** for non-Apache formats; keep Apache regex where it's fine. |
| 14 | **Locate-Then-Detect** | Attention-based localization of the attack span in a request | Explainability + precision for web attacks | **No** | Rule layer emits attack type but not span | Add a lightweight attention-head output over the URL/body tokens for explainability; cheap and very paper-friendly. |
| 15 | **Detecting Web Attacks with E2E DL** | Char-level CNN directly on raw HTTP | Complements template-level scoring | **Partial** | Rule layer handles payloads; no learned payload model | Add a char-CNN payload head as a third ensemble member; replace the hardcoded XSS/SQLi severity weights with learned logits. |

---

## C. Critical Weaknesses (ranked by impact)

Legend: **[M]** modeling · **[D]** data pipeline · **[E]** evaluation · **[S]** systems/deployment.

1. **[M] Integer-ID template vocabulary with a single `unknown_id` bucket.** This is the single largest quality ceiling. Every unseen template is indistinguishable from every other, and recovery requires a teacher retrain. Fix: semantic embeddings of template *text* (paper #2, #5). Impact: huge. Novelty: medium.
2. **[E] No PR-AUC, ROC-AUC, calibration, or threshold sweep anywhere.** `backtest_harness.py` reports only point F1. The declared targets in `train_openstack.yaml:71-76` are fiction. You cannot publish without this.
3. **[M] Students never update after initial fit.** `student_model.py` has the reservoirs but nothing consumes them on the student side. The teacher is updated weekly; students are immortal. This is the most commonly cited production failure mode (paper #8).
4. **[M] "Unknown = anomaly" conflation.** The `unknown_template_ratio ≥ 0.5 → anomaly` rule (`teacher_model.py:521-533`) makes novelty indistinguishable from maliciousness. A legitimate deploy of a new endpoint is a Sev-1 false positive waterfall. Paper #9 directly addresses this.
5. **[D] Regex-only parser.** `log_parser_service.py` is Apache/Nginx hand-written regex. Anything outside those formats degrades silently. Paper #13 is essentially a warning label for this design.
6. **[E] No baselines, no ablations.** You cannot claim teacher+student KD is helpful without turning off the student and running. You cannot claim the Isolation Forest pulls weight. You cannot claim the manifest is helpful. None of these comparisons exist.
7. **[M] Ensemble weights are magic numbers.** `rule=0.3–1.5, iso=0.5, transformer=0.7` are hand-set constants (`teacher_model.py:575-601`). No learned calibration, no per-tenant adjustment. For a paper this is indefensible.
8. **[S] Teacher is never used at inference in ACTIVE phase.** `CollaborLog`-style escalation is free performance you are not taking. A student with high entropy should be able to defer to the teacher.
9. **[D] Warmup distribution is whatever arrives first, filtered only by `baseline_eligible`.** No stratified sampling, no reservoir-aware warmup. Small-tenant warmup is dominated by whichever sessions happen to fill the buffer first.
10. **[E] No cross-system / cross-tenant transfer evaluation.** You have multi-tenant architecture but your backtest replays each project independently. The most interesting claim your system *could* make — "one teacher transfers across systems" — is never tested.

Honourable mentions that didn't make the top 10: (a) hardcoded `MAX_UNKNOWN_TEMPLATE_RATIO=0.5`, (b) no latency histogram, (c) `contamination='auto'` with silent fallback to 0.05, (d) `incident_bucket_minutes=15` hardcoded in the harness, (e) KD temperature fixed to 3.0 without sweep, (f) student vocab frozen with no expansion path.

---

## D. Target Architecture

Keep the service topology. Keep the WARMUP → TRAINING → ACTIVE lifecycle. Keep the manifest-aware baseline-eligibility gate. Keep the rule layer. Everything else is on the table.

### D.1 Model stack

```
                    ┌─────────────────────────────────────────┐
                    │   Parser (Drain3 + Apache regex + BPE)  │
                    └──────────────────┬──────────────────────┘
                                       │ template_text + payload
                                       ▼
              ┌───────────────────────────────────────────────┐
              │ Frozen template encoder (MiniLM-L6 / distil)  │  ← paper #2,#5
              │ emits 384-d template vectors; kNN over cache  │
              └──────────────────┬────────────────────────────┘
                                 │ template embeddings
                                 ▼
              ┌───────────────────────────────────────────────┐
              │ Session encoder = small transformer over      │  ← paper #4 HitAnomaly
              │  sequence of template vectors (window=32)     │     style hierarchy
              └──────────────────┬────────────────────────────┘
                                 │ session embedding h
                                 ▼
      ┌──────────────┬───────────┴────────────┬────────────────────┐
      ▼              ▼                        ▼                    ▼
 Teacher head   Student heads (1/cluster)  Char-CNN payload     Rule layer
 (shared)       = LogMoE experts + gate    head (paper #15)     (current)
      │              │                        │                    │
      └──────────────┴──────────┬─────────────┴────────────────────┘
                                ▼
                      Learned calibration head
                      (logistic / temperature scaled)
                      → P(malicious), P(novel), P(benign)
                                ▼
                    Decision policy (reject / escalate / alert)
```

### D.2 Training flow
- **Stage 0 — pretraining (offline).** MLM on HDFS+OpenStack+your own historical logs. Frozen encoder output only; no CE head. Replaces the current causal teacher for representation learning.
- **Stage 1 — meta-training (offline, across tenants).** MAML/Reptile over N historical tenants, inner-loop = 5–50 gradient steps on a small support set, outer-loop optimizes fast-adaptation. Produces the initial per-tenant expert weights. Paper #7.
- **Stage 2 — per-tenant warmup.** Uses meta-initialized expert and the frozen encoder. Warmup now *specializes* rather than trains from scratch, so the `warmup_threshold` can drop by an order of magnitude.
- **Stage 3 — online student updates.** Continuous updates from `clean_normal_reservoir` on a cadence (every N clean events, e.g. 500). Guarded by KL drift against prior checkpoint to avoid catastrophic forgetting. Paper #8.
- **Stage 4 — teacher refresh.** Keep the existing weekly scheduler, but the teacher is now only the encoder + shared head; per-tenant drift is handled online in Stage 3.

### D.3 Cold-start and warmup
Replace the "collect 500 eligible events then train" rule with a **two-track warmup**:
- **Track A — meta-adapter:** run the meta-initialized expert in detection from event 1 using frozen encoder + manifest priors. This is the active scorer.
- **Track B — background collector:** accumulate `clean_normal_reservoir` and upgrade the expert when either (a) 500 samples reached, OR (b) the adapter's rolling entropy on clean traffic stabilizes.

The `baseline_eligible` + manifest logic stays. The change is that the expert is *never* a cold random init.

### D.4 Open-world handling (replaces `unknown_id` hack)
- New templates compute cosine similarity vs. the tenant's template cache via the frozen encoder.
- If max similarity > τ: inherit the nearest template's statistics. **This is not anomaly.**
- If max similarity < τ: classify as `novel`, *not* malicious. The calibration head emits P(novel) and P(malicious) separately.
- Decision policy: `novel` → log + quarantine + fast-track into reservoir; `malicious` → alert.
- Remove the `MAX_UNKNOWN_TEMPLATE_RATIO=0.5` hardcoded penalty entirely.

### D.5 Thresholding / calibration
Replace hand-set 0.5 ensemble threshold with:
- **Per-tenant temperature scaling** fit on the calibration split (you already split 70/15/15 in `student_model.py:403-436`).
- **Learned logistic head** combining `[teacher_nll, student_nll, iso_score, rule_max_weight, payload_cnn_score, unknown_fraction, session_len, traffic_class_onehot]`.
- **Operating point chosen per tenant** from a target FPR (e.g. 1/10k events) instead of a fixed F1 point.
- Export ECE (expected calibration error) as a first-class metric in the backtest.

### D.6 Tenant adaptation (LogMoE-style)
One expert per *cluster of similar tenants*, not per tenant:
- Cluster tenants by endpoint-manifest Jaccard similarity and volume profile.
- Each cluster has a shared expert; the gate network routes per-session.
- Small/new tenants join existing experts instead of training from scratch.
- Large tenants can be promoted to their own expert.

This is a direct retrofit of `student_model.py` → `expert_model.py` with a routing wrapper in `multi_tenant_detector.py`.

### D.7 Runtime escalation (CollaborLog)
When the student/expert emits low-confidence scores (entropy above threshold OR student/teacher disagreement > δ), reroute to the teacher encoder + a heavier scoring head before final decision. Budget: escalate at most X% of traffic. Directly addresses weakness #8.

### D.8 Attack rules + payload model
Keep the regex layer as a high-precision shortcut. But:
- Its severity weights (`ensemble_detector.py:86-93`) become *features* for the calibration head, not hard-coded scalar votes.
- Add a char-CNN over the URL path + query string (paper #14/15). Trained on Locate-Then-Detect-style labelled web attack datasets (CSIC 2010, ECML/PKDD 2007, FWAF). Output is both (a) a scalar attack score and (b) a per-token attention map for explanation.

### D.9 Fallback behaviour
- If encoder checkpoint missing → fall back to current integer-vocab teacher, log a warning at startup (`server_multi_tenant.py:263-347` is the right place).
- If expert gate misroutes or expert missing → fall back to teacher head.
- If calibration head unfit → fall back to the existing 0.5 ensemble threshold.
- Every fallback must emit a counter so production can monitor how often they fire.

### D.10 What stays vs. what goes

**Stays.**
- Service topology, WARMUP/TRAINING/ACTIVE lifecycle, per-project sessions, manifest seeding, baseline eligibility, route canonicalization, Isolation Forest as one input among many, the rule layer as a feature source, the reservoirs, the weekly teacher scheduler.

**Goes.**
- Integer-ID `unknown_id` collapse.
- Hardcoded `MAX_UNKNOWN_TEMPLATE_RATIO`.
- Hardcoded ensemble weights and the `> 0.5` rule.
- "One student per project from scratch" training.
- "Teacher is only used during warmup" flow.
- Treating new templates as anomalies.
- Declared-but-uncomputed metric targets in yaml configs.

---

## E. Prioritized Implementation Roadmap

Each item lists: **files** · **benefit** · **difficulty (1-5)** · **research value (1-5)** · **op risk (1-5)**.

### Phase 1 — high-impact, low-risk (engineering hygiene + credibility)

1. **Real evaluation metrics in the backtest.**
   - Files: `scripts/backtest_harness.py`, new `scripts/metrics.py`.
   - Add PR-AUC, ROC-AUC, ECE, alert volume over time, p50/p95/p99 latency histograms, per-traffic-class breakdowns.
   - Diff: 4 · Research: 5 · Op risk: 1.

2. **Baselines and ablations in the backtest.**
   - Files: `scripts/backtest_harness.py`, new `--ablation` flags.
   - Implement: rule-only, iso-only, teacher-only, student-only, no-manifest, no-canonicalization.
   - Diff: 3 · Research: 5 · Op risk: 1.

3. **Online student updates from `clean_normal_reservoir`.**
   - Files: `realtime_anomaly_detection/models/student_model.py`, `multi_tenant_detector.py:1076-1110`.
   - Update every N clean samples (e.g. 500), with KL-drift guardrail vs. previous checkpoint.
   - Diff: 3 · Research: 4 · Op risk: 3. **Mitigate with feature flag per tenant.**

4. **Split `unknown` from `anomaly` in the decision path.**
   - Files: `teacher_model.py:521-533`, `student_model.py`, `multi_tenant_detector.py:1242-1273`.
   - Emit two scores: `novel_score`, `malicious_score`. Keep legacy field for compatibility.
   - Diff: 2 · Research: 3 · Op risk: 2.

5. **Drain3 for non-Apache formats.**
   - Files: `backend/app/services/log_parser_service.py`.
   - Keep the Apache/Nginx fast paths; route unknown formats through Drain3.
   - Diff: 3 · Research: 3 · Op risk: 2.

6. **Learned calibration head replacing `> 0.5` rule.**
   - Files: new `realtime_anomaly_detection/models/calibrator.py`, wire into `teacher_model.detect`, `student_model.detect`, ensemble combine path.
   - Start with logistic regression on the calibration split (you already have it: `student_model.py:403-436`).
   - Diff: 3 · Research: 4 · Op risk: 2.

### Phase 2 — research-grade upgrades

7. **Semantic template encoder (frozen MiniLM / distilled LogBERT).**
   - Files: new `realtime_anomaly_detection/models/template_encoder.py`, refactor teacher/student to consume vectors instead of integer IDs, refactor `multi_tenant_detector._canonicalize_path` to feed text to encoder.
   - Biggest quality lever in the system.
   - Diff: 4 · Research: 5 · Op risk: 3. **Mitigate by keeping integer path as fallback.**

8. **Runtime teacher escalation (CollaborLog pattern).**
   - Files: `multi_tenant_detector._detect_with_student:1477-1511`.
   - On low-confidence student output, re-score with teacher; budget escalation rate.
   - Diff: 2 · Research: 4 · Op risk: 2.

9. **Hierarchical session encoder (HitAnomaly-lite).**
   - Files: `ensemble_detector.py:TemplateTransformer`, `teacher_model.py:264-289`.
   - Two-level: template-content → session. Only adopt after #7; they compose.
   - Diff: 4 · Research: 4 · Op risk: 3.

10. **Char-CNN payload model + labelled attack training.**
    - Files: new `realtime_anomaly_detection/models/payload_cnn.py`; training script; CSIC 2010 + ECML/PKDD + FWAF data loaders.
    - Diff: 4 · Research: 4 · Op risk: 2.

11. **Attention-based attack-span localization head.**
    - Files: `payload_cnn.py`.
    - Emit per-token attention; return spans with the detection for explainability.
    - Diff: 3 · Research: 4 · Op risk: 1.

### Phase 3 — ambitious / paper-novel

12. **LogMoE cluster-experts + routing gate.**
    - Files: refactor `student_model.py` → `expert_model.py`, new `gate.py`, rewire `multi_tenant_detector.py:_detect_with_student`.
    - Diff: 5 · Research: 5 · Op risk: 4.

13. **MetaLog-style cross-tenant meta-training.**
    - Files: new `scripts/meta_train.py`, offline pipeline only. Runtime just loads a meta-initialized expert.
    - Diff: 5 · Research: 5 (this is the novelty bet) · Op risk: 2 because it's offline.

14. **Open-world rejection head (LogOW).**
    - Files: `calibrator.py` extension → three-way classifier.
    - Diff: 3 · Research: 4 · Op risk: 2.

15. **Cross-system transfer eval in backtest.**
    - Files: `scripts/backtest_harness.py` — add a `--transfer src→tgt` mode.
    - Claim enabler for any paper story.
    - Diff: 3 · Research: 5 · Op risk: 1.

---

## F. Experiment Plan

### F.1 Datasets
- **HDFS** (block-level anomalies) — covers classical sequence-LM literature.
- **BGL** — higher unstable-log burden; tests robustness (paper #5).
- **Thunderbird** — long sessions, tests hierarchical encoder (paper #4).
- **OpenStack** — your existing config path; multi-component.
- **CSIC 2010 + ECML/PKDD 2007 + FWAF** — web-attack payloads for rule/CNN head.
- **Your production replay corpus** — multi-tenant realism. Anonymized.

### F.2 Baselines
Per-dataset F1 + PR-AUC + ROC-AUC + ECE + p95 latency vs.:
1. DeepLog reimplementation (top-k deviation, LSTM).
2. LogBERT (MLM hypersphere).
3. LogAnomaly (template2vec + count+sequence).
4. Current LogGuard (teacher+student+rules+IF, frozen).
5. Proposed LogGuard (full stack).

### F.3 Ablations (must-have)
On the production replay corpus:
- `−semantic` (integer vocab)
- `−meta-init` (cold start as today)
- `−online_student` (students frozen)
- `−teacher_escalation`
- `−manifest` (no endpoint priors)
- `−hierarchical` (flat session encoder)
- `−payload_cnn`
- `−calibrator` (hand-set weights)
- `−rule_layer`
- `−isolation_forest`

Each ablation reports Δ on all metrics to demonstrate which components earn their keep.

### F.4 Replay setup
- Chronological multi-tenant replay. Strict no-peeking: the scorer sees events only in timestamp order.
- Incident-level F1 (already in `backtest_harness.py:423-457`) plus event-level.
- Warmup budget capped per tenant; report results as a function of warmup size (the core MetaLog claim).

### F.5 Metrics
- Quality: Precision, Recall, F1, PR-AUC, ROC-AUC, ECE.
- Operational: p50/p95/p99 per-event latency, memory, cold-start time, false-alert rate per hour.
- Explainability: agreement between rule layer and attention-span localization (IoU on span ground truth where available).
- Stability: drift metric — model performance on the last 10% of replay vs. the first 10% on clean traffic.

### F.6 Failure analyses
- Unknown-template bursts from a legitimate deploy → expected FP blow-up on legacy system, graceful handling on new system. Directly exercises weakness #4.
- Tenant-similar-but-different-traffic → tests LogMoE routing correctness.
- Adversarial probes: encoded SQLi, Unicode evasion → tests rule + CNN complementarity.
- Cold-start new tenant with N∈{50, 100, 500, 2000, 10000} warmup events → central MetaLog claim.

### F.7 Latency / cost
- Measure inference path lengths *with and without* escalation, *with and without* semantic encoder.
- Publish memory footprint for expert-per-cluster vs. expert-per-tenant.
- Publish training cost for meta-init vs. per-tenant from-scratch.

### F.8 What claims each experiment would support

| Experiment | Paper claim it licenses |
|---|---|
| Cross-tenant meta-init + warmup curves | "LogGuard reaches production-quality anomaly scoring with ≪ prior cold-start budgets." |
| −semantic ablation | "Semantic template embeddings are necessary for open-world web log settings." |
| −online_student ablation | "Online student adaptation is the dominant factor in long-horizon stability." |
| Teacher escalation experiment | "Large/small collaboration recovers X% of teacher quality at Y% of teacher cost." |
| Rule+CNN complementarity | "Regex rules and learned payload models are independently useful and combine monotonically." |
| ECE per-tenant calibration | "Per-tenant temperature scaling is required; hand-set thresholds are mis-calibrated on K out of N tenants." |
| Manifest ablation | **Unique to this repo** — "Endpoint manifest priors reduce cold-start false-positive rate by X×." I have seen *no* paper make this claim. |

The manifest-seeding story is the most underrated lever in the repo; it's also the most defensible "we did something new" claim.

---

## G. Final Recommendation — one bet

**Build LogGuard into a Cross-Tenant Meta-Learned Open-World Detector with Endpoint-Manifest Priors.**

Concretely: one paper, one architectural direction, one marketing line. The spine is:

1. **Frozen semantic template encoder** (distilled LogBERT / MiniLM) replacing integer vocab.
2. **Meta-trained expert pool** across historical tenants, routed by a lightweight gate — your per-project student becomes a per-cluster expert with a meta-initialization.
3. **Endpoint manifest priors** as a structured inductive bias on warmup distribution — this is the unique thing only your repo has, and the paper angle nobody else can copy.
4. **Online expert updates** from clean reservoirs with drift guardrails.
5. **Calibrated three-way decision head** (`benign / novel / malicious`) replacing the hardcoded ensemble threshold.
6. **Teacher escalation** as a quality safety valve.
7. **Rules + char-CNN payload head** as high-precision complements feeding the calibrator.

**Why this bet and not another?**

- It matches *your existing strengths*. You already have multi-tenant lifecycle, manifest seeding, reservoirs, and a teacher/student split. The target design uses all of them — nothing is thrown away.
- It's the only direction that lets you tell a *defensible novelty story* at ICSE/ASE. "Yet another LogBERT variant" is unpublishable. "Meta-learned multi-tenant open-world detector with endpoint-manifest priors and calibrated novelty/malice separation" is both novel and directly motivated by production pain.
- It *fixes the real production problems* simultaneously: open-world FPs, cold-start pain, unstable logs, miscalibrated thresholds, and frozen students. Every item on the critical-weakness list is addressed by at least one leg of the design.
- It degrades gracefully. Every component has a working fallback (integer vocab, per-tenant student, fixed thresholds, teacher-only scoring). You can land it incrementally without a flag day.
- The unique differentiators — **manifest priors as training-distribution control** and **meta-learned cross-tenant initialization over manifest-typed tenants** — are things no paper in the reviewed set combines. That is a paper hook.

**What I would *not* do:**
- I would not pivot to an end-to-end char model (OneLog). It throws away the rule layer and the manifest semantics you already own.
- I would not adopt HitAnomaly's full hierarchical stack before doing the semantic encoder — the encoder change dominates.
- I would not spend engineering time on a "better Isolation Forest". Isolation Forest is fine as one feature; it is not a quality frontier.
- I would not add a reinforcement-learning loop. Too much operational risk, low research payoff on this kind of data.

**Execution order if I had to freeze it today:**
Phase 1 items 1, 2, 3, 4 → then item 7 (semantic encoder) → then items 6, 8 → then the Phase 3 meta-training + MoE gate. Experiments (Section F) run alongside Phase 1 so that every subsequent merge has a number attached.

This is the single clearest path from "multi-service log anomaly product" to "defensible research contribution with production teeth."

