Codebase Understanding                
                                                                                                                         
  LogGuard is a three-layer hybrid detection system:                                                                       
  - Rule engine → deterministic regex on URL-decoded paths (always overrides)                                               
  - Teacher Transformer → causal decoder on template sequences (global, 4-layer, d=256)                                    
  - Student Transformer → per-project distilled model (2-layer, d=128) + project-specific Isolation Forest                 
    Logs flow: ingest → parse → template normalize → session window → ensemble score → calibrate threshold → incident bucket 
  → websocket fanout                                                                                                       
                                                                                                                           
  -- Improvement Areas                                                                                                        
                                                                                                                           
  1. Detection Accuracy (High Impact)                                                                                      
    A. Unknown template blind spot — The MAX_UNKNOWN_TEMPLATE_RATIO=0.5 guard suppresses the transformer when ≥50% of session
   tokens are unseen templates. This is exactly backwards: a probe scanning novel endpoints is the highest-risk scenario,  
  yet it gets zero transformer signal.                                                                                     
                                  
  Fix: Instead of disabling the transformer, treat unknown tokens as high-entropy signal. Assign unknown-template sequences
   a penalty score proportional to unknown_ratio * max_nll_observed_for_project. This gives a floor anomaly signal rather
  than silence.                                                                                                            
                                  
  B. Rule confidence is uniform and dominates — confidence = min(attack_count * 0.3 + 0.4, 1.0) gives 0.7 for a single ../ 
  hit and the same for UNION SELECT + DROP TABLE. The ensemble weight is then max(confidence, 1.0), capped at 1.0, making
  any rule hit weight 1.0 vs transformer's 0.7 and IF's 0.5. A path traversal on a static asset drowns out the other       
  detectors.                      
                                                                                                                           
  Fix: Introduce severity tiers (LOW/MED/HIGH/CRITICAL) to rules. SQL injection and command injection = HIGH (weight 1.5+),
   path traversal = MED (weight 0.8), generic XSS = depends on context. Don't use a floor of 1.0 for any single hit.     
                                                                                                                           
  C. Session features miss temporal density — The 11/16-feature vector for Isolation Forest captures request count and
  error rate but not rate of change. A slow-scan attacker making 1 request/hour looks identical to a normal user at the    
  feature level.                                                                                                           
                                  
  Fix: Add inter-request time delta stats to session state (mean, std, min). Add requests_last_5min and errors_last_5min   
  using a timestamp deque. That's 4 new features for v4 of the feature schema.                                           
                                                                                                                           
  D. Isolation Forest contamination is fixed at 0.1 — During warmup, the system deliberately collects clean baseline logs,
  yet the forest still trains assuming 10% contamination. This systematically mislabels normal traffic as anomalous.       
                                                                                                                           
  Fix: Use contamination='auto' (scikit-learn ≥1.3) or compute empirical contamination from the rule-flagged ratio in the
  calibration split. Something like contamination = max(0.01, min(0.1, flagged_count / total_calibration_count)).          
                                                                                                                           
  E. Positional encoding is learned, not sinusoidal — For the sequence transformer, learned positional embeddings require
  seeing positions in training. The window is maxlen=20 so sequences shorter than 20 will have undertrained positional     
  params for high-position indices. Rotary position embeddings (RoPE) or ALiBi would generalize better and handle          
  variable-length windows without the cold-start degradation.
                                                                                                                           
  ---             
  2. Architecture (Medium-to-High Impact)
                                         
  F. Single RLock serializes all projects — _get_or_create_session() acquires one global threading.RLock for every       
  detection call, serializing throughput across all tenants. At scale this is a hard ceiling.                              
                                                                                                                         
  Fix: Use per-project locks — a defaultdict(threading.RLock) keyed by project_id. Global lock is only needed for creating 
  project entries in the dict, not for every session read.                                                               
                                                                                                                           
  G. Session expiry is O(N) on the hot path — Expired session cleanup runs synchronously in every detection call, iterating
   all sessions for a project.                                                                                             
                                                                                                                           
  Fix: Move expiry to a background thread running every 60s. In the hot path, only evict if last cleanup was >5 minutes
  ago.                                                                                                                     
                                                                                                                           
  H. Incident cache has no eviction — incident_cache is an unbounded in-memory dict. Over weeks, a busy project accumulates
   thousands of stale 15-minute buckets.                                                                                   
                                                                                                                           
  Fix: Add an LRU eviction policy or periodic TTL-based cleanup (e.g., evict any bucket > 2 hours old on a background
  timer).                                                                                                                  
                                                                                                                           
  I. _save_projects() called on every stat update — This serializes the entire projects dict to JSON on what could be
  per-batch (or worse, per-log) calls. On a server with 50 projects each with large vocabs, this is expensive I/O.         
                                                                                                                           
  Fix: Debounce saves — mark projects "dirty" and flush dirty projects to disk every 30 seconds on a background thread.
  Only do a synchronous save on graceful shutdown.                                                                         
                                                                                                                           
  J. Single training thread blocks multi-project training — Training 5 projects serially means a 10-minute training queue
  behind one slow project.                                                                                                 
                                                                                                                           
  Fix: Use a ThreadPoolExecutor with max_workers=min(4, cpu_count) for the training queue. Training is CPU-bound and
  GIL-releasing (PyTorch), so threads genuinely parallelize.                                                               
                                                                                                                           
  K. Teacher training has a race condition — During update_from_student_logs(), teacher weights are modified on the
  training thread while the inference path may call get_soft_labels() with no synchronization.                             
                                                                                                                           
  Fix: Keep two copies of the teacher (current + shadow). Train on shadow, then swap under lock. This is the standard
  "double-buffer" pattern for online model updates.                                                                        
                                                                                                                           
  ---                             
  3. Model Quality (Medium Impact)                                                                                         
                                  
  L. KD soft label temperature mismatch — Teacher generates soft labels with F.softmax(logits, dim=-1) (T=1.0), but during
  KD loss computation the student applies T=3.0. The intent of KD is to use the teacher's temperature-softened
  distribution, so teacher inference should also use T=3.0 during label generation.                                      
                                                                                                                           
  Fix: In get_soft_labels(), apply temperature: F.softmax(logits / T, dim=-1) with the same T used in training loss.
                                                                                                                           
  M. Vocab size mismatch zero-padding — When teacher vocab > student vocab, teacher soft labels are truncated (losing      
  probability mass). When teacher vocab < student vocab, labels are zero-padded (injecting spurious probability mass into
  meaningless tokens).                                                                                                     
                                  
  Fix: Map vocabularies explicitly. Maintain a shared template registry and use the intersection for distillation. Tokens  
  only in student get uniform(1/|student_vocab|) teacher target, not zero or truncation.                                 
                                                                                                                           
  N. No streaming/online learning — The student trains once during the TRAINING phase, then is static during ACTIVE.
  Traffic distributions shift (new endpoints deployed, seasonal patterns), but the student never adapts.                   
                                                                                                                           
  Fix: Implement reservoir-based continual learning. Every N hours (e.g., 6), fine-tune the active student on a small
  replay buffer from clean_normal reservoir (already collected). 1 epoch, small LR (1e-5). This costs ~seconds for the     
  small student model.                                                                                                     
                                  
  ---                                                                                                                      
  4. Observability (Lower Impact, High Ops Value)
                                                 
  O. Session state is ephemeral — Pod restart during warmup loses all collected session context. Projects restart their  
  20-log sliding window from zero, resetting clean_baseline_count and hours coverage.                                      
                                                                                                                         
  Fix: Periodically checkpoint session aggregates (not full per-IP sessions, but per-project stats like                    
  clean_baseline_count, observed_hours, distinct_template_count) to disk alongside projects.json. On startup, restore these
   stats.                                                                                                                  
                                  
  P. No per-project detection latency metrics — There's no instrumentation on how long each component takes (rule engine,  
  transformer, isolation forest). Slow detections are invisible.                                                         
                                                                                                                           
  Fix: Add time.perf_counter() spans around each component and expose them via a /internal/metrics Prometheus endpoint. At
  minimum, track P50/P99 latency per project and per component.                                                            
                                                                                                                           
  Q. Dead code: adaptive_detector.py / server_adaptive.py — This is a fully-implemented alternate detector that doesn't
  share state with the multi-tenant system. It adds ~1000 lines of maintenance burden and could confuse future             
  contributors.                                                                                                            
                                  
  Fix: Delete or move to archive/ and document the decision in CLAUDE.md.                                                  
                                                                                                                         
  ---                                                                                                                      
  Prioritized Roadmap             
                                                                                                                           
  ┌──────────┬────────────────────────────────────────────────────────┬─────────┬─────────────────────────────────┐
  │ Priority │                          Item                          │ Effort  │             Impact              │
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤      
  │ 1        │ Fix unknown-template blind spot (F→score, not silence) │ Small   │ Critical                        │        
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤
  │ 2        │ Per-project locks instead of global RLock              │ Small   │ High (throughput)               │        
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤      
  │ 3        │ Rule severity tiers + remove weight floor              │ Medium  │ High (false positive reduction) │        
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 4        │ Fix KD temperature mismatch                            │ Trivial │ High (model quality)            │        
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 5        │ Background session expiry                              │ Small   │ Medium (latency)                │      
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 6        │ Adaptive contamination for Isolation Forest            │ Small   │ Medium (accuracy)               │      
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 7        │ Debounced _save_projects()                             │ Small   │ Medium (I/O)                    │
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 8        │ ThreadPoolExecutor for training queue                  │ Small   │ Medium (throughput)             │      
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 9        │ Double-buffer teacher for race-free updates            │ Medium  │ Medium (correctness)            │      
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 10       │ Temporal density features (v4 schema)                  │ Medium  │ Medium (accuracy)               │      
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 11       │ Reservoir-based continual learning for student         │ Medium  │ Medium (long-term accuracy)     │      
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 12       │ LRU eviction on incident cache                         │ Trivial │ Low (memory)                    │      
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 13       │ Fix vocab alignment in distillation                    │ Medium  │ Low-Medium                      │
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 14       │ Session state checkpointing                            │ Medium  │ Low (ops)                       │      
  ├──────────┼────────────────────────────────────────────────────────┼─────────┼─────────────────────────────────┤        
  │ 15       │ Delete dead adaptive_detector.py                       │ Trivial │ Maintenance                     │
  └──────────┴────────────────────────────────────────────────────────┴─────────┴─────────────────────────────
