# Detailed Algorithm Design Report

This document is the detailed reference for how the matching layer works in `algorithem_pipeline`, which files implement each part, and where flexibility was intentionally designed into each algorithm.

## 1. Code Map

Core files:

- `algorithem_pipeline/algorithem_pipeline/algorithms/base.py`
  - Shared matcher contract. Every algorithm exposes `match(target_graph, pattern_graph)` and returns `TechniqueMatch`.
- `algorithem_pipeline/algorithem_pipeline/algorithms/baseline_exact.py`
  - Exact structural baseline.
- `algorithem_pipeline/algorithem_pipeline/algorithms/core_approximate.py`
  - Approximate tree matcher with edit-distance style scoring.
- `algorithem_pipeline/algorithem_pipeline/algorithms/scale_multipattern.py`
  - One-pass subtree hashing for large pattern sets.
- `algorithem_pipeline/algorithem_pipeline/algorithms/structure_adaptive.py`
  - Density-aware matcher that switches strategy based on graph shape.
- `algorithem_pipeline/algorithem_pipeline/algorithms/behavioral_anchor_fusion.py`
  - Hybrid matcher designed for this project case: malicious-pattern anchors, object features, edge semantics, local graph shape, and realtime-friendly partial matching.
- `algorithem_pipeline/algorithem_pipeline/io/tree_adapter.py`
  - Common graph-to-forest conversion used by all matchers.
- `algorithem_pipeline/algorithem_pipeline/service/matcher_service.py`
  - Orchestrates graph loading, pattern loading, algorithm execution, and ranking.
- `algorithem_pipeline/algorithem_pipeline/evaluation/benchmark.py`
  - Wraps per-technique matches into benchmark output.
- `algorithem_pipeline/algorithem_pipeline/evaluation/metrics.py`
  - Shared metrics such as top-1 accuracy.

## 2. Shared Matching Model

Before any algorithm runs, graphs are normalized and converted into a rooted forest representation.

Shared flow:

1. Raw Sysmon logs are parsed and converted into graph payloads.
2. `graph_loader.py` normalizes nodes and edges into `GraphData`.
3. `tree_adapter.py` converts the graph into `TreeNode` forests using `HAS_ROOT` and indegree heuristics.
4. Each matcher scores the target graph against one pattern graph.
5. The service aggregates all results and sorts the ranked techniques.

Important design choice:

- The algorithm layer operates on normalized `GraphData` and `TreeNode`, not on raw log format.
- That makes the matchers independent from whether the source graph came from offline raw logs, streamed events, or prebuilt JSON.

## 3. Baseline Exact

Implementation file:

- `algorithem_pipeline/algorithem_pipeline/algorithms/baseline_exact.py`

How it works:

1. Build rooted forests for target and pattern.
2. Compute a canonical subtree hash for every target subtree.
3. Compute the same canonical hash for each pattern root.
4. Declare a match only when the canonical subtree hash appears exactly in the target index.
5. Score = matched pattern roots / total pattern roots.

Key internal functions:

- `_node_signature(node)`
  - Encodes the node as `type|normalized_label`.
- `_canonical_hash(node)`
  - Recursively hashes the current node plus sorted child hashes.

Why it exists:

- This is the strict baseline.
- It tells you what performance and accuracy look like when no approximation is allowed.

Designed flexibility:

- The node signature is isolated in `_node_signature`, so you can broaden or tighten exactness by changing what fields are included.
- The matcher indexes every target subtree once, so the exact policy can be preserved even if the scoring formula changes later.
- Forest-based matching allows techniques with multiple roots to be handled without rewriting the matcher.

Current behavior tradeoff:

- Very interpretable and deterministic.
- Very brittle when labels differ slightly, nodes are missing, or the graph shape is perturbed.

Best use case:

- Regression baseline.
- Clean datasets where graph construction is stable and labels are normalized consistently.

## 4. Core Approximate

Implementation file:

- `algorithem_pipeline/algorithem_pipeline/algorithms/core_approximate.py`

How it works:

1. Build rooted forests for target and pattern.
2. Enumerate every target subtree candidate.
3. For each pattern root, compare it with all target candidates.
4. Use an edit-distance style score that combines:
   - node substitution cost,
   - child assignment cost,
   - penalties for missing or extra children.
5. Accept the best candidate if either:
   - `similarity >= threshold`, or
   - `missing_ratio <= missing_ratio_k`.
6. Score = matched pattern roots / total pattern roots.

Key internal functions:

- `_node_cost(a, b)`
  - Penalizes node type mismatch and label mismatch.
- `_child_match_cost(a_children, b_children)`
  - Uses exhaustive assignment for small fan-out, greedy matching for larger fan-out.
- `_edit_distance(a, b)`
  - Combines own-node cost and child-match cost.
- `_similarity(target_subtree, pattern_subtree)`
  - Normalizes distance into a similarity score and computes missing ratio.

Why it exists:

- Real graphs are noisy.
- Event grouping, entity merge behavior, and raw log variation can slightly alter structure even when the attack behavior is similar.

Designed flexibility:

- `threshold` controls how strict the acceptance is.
- `missing_ratio_k` allows partial-structure acceptance even when raw similarity is not high enough.
- The child matching routine deliberately switches strategy by fan-out size:
  - exact search for small branching,
  - greedy fallback for larger branching.
- `_node_cost` is centralized, so domain-specific weighting can be adjusted without changing the outer matcher.

Current behavior tradeoff:

- Much more tolerant than exact hashing.
- More expensive because it compares pattern roots against all target candidates.
- Still tree-oriented, so non-tree graph semantics are simplified by the forest adapter.

Best use case:

- Matching under missing events, extra events, or slightly changed labels.
- Datasets where topology is mostly preserved but not identical.

## 5. Scale Multi-Pattern

Implementation file:

- `algorithem_pipeline/algorithem_pipeline/algorithms/scale_multipattern.py`

How it works:

1. Compile a pattern graph into a set of subtree hashes.
2. Traverse the target graph once and compute subtree hashes for all target nodes.
3. Intersect target subtree hashes with the compiled pattern hash set.
4. Score = number of hit hashes / number of pattern hashes.
5. Collect matched node ids from every hit hash.

Key internal functions:

- `_compact_signature(node)`
  - Encodes node type and normalized label.
- `_hash_subtree(node, cache, hit_nodes)`
  - Recursively hashes each subtree and records which target node ids produced that hash.
- `_compile_pattern(pattern_graph)`
  - Precomputes the pattern hash set once per technique.

Why it exists:

- The approximate matcher is flexible but comparatively expensive.
- This matcher is optimized for reuse when the system needs to compare a target graph against many patterns.

Designed flexibility:

- Pattern compilation is cached in `self._pattern_index`, so repeated use of the same pattern set is cheap.
- Hash generation is isolated, which makes it straightforward to switch to richer signatures later.
- The algorithm cleanly separates compile-time work and run-time target traversal, which is useful if the pattern catalog grows.

Current behavior tradeoff:

- Very fast and scalable for large catalogs.
- Matching is still exact on subtree signature, so semantic variants are invisible unless the signature function is broadened.
- Because it counts hash intersections, it behaves more like structural fingerprint overlap than alignment.

Best use case:

- Multi-pattern screening.
- Situations where speed and catalog scale matter more than semantic tolerance.

## 6. Structure Adaptive

Implementation file:

- `algorithem_pipeline/algorithem_pipeline/algorithms/structure_adaptive.py`

How it works:

1. Compute target graph density with `graph_density(target_graph)`.
2. If the graph is dense:
   - delegate to a more permissive `CoreApproximateMatcher` fallback.
3. If the graph is sparse:
   - extract contextual token counters around each subtree,
   - compare pattern and target candidates using weighted Jaccard similarity,
   - accept a match when token overlap reaches the threshold.
4. Score = matched pattern roots / total pattern roots.

Key internal functions:

- `_tokenize(node)`
  - Extracts tokens from node type, label, and selected properties such as `event_id`, `command_line`, `image_path`, `key_path`, `file_path`, `destination_ip`.
- `_aggregate_tokens(root, depth=2)`
  - Builds a contextual token profile from the subtree neighborhood.
- `_weighted_jaccard(a, b)`
  - Measures weighted token overlap.

Why it exists:

- Sparse graphs and dense graphs do not behave the same.
- A single scoring strategy tends to overfit one graph regime and underperform on the other.

Designed flexibility:

- The density threshold is explicit and easy to tune.
- Sparse-mode similarity is token-based, which makes it easy to add or remove fields from `_tokenize`.
- Dense-mode delegates to `CoreApproximateMatcher(threshold=0.58, missing_ratio_k=0.45)`, so the fallback can be tuned independently from the default approximate matcher.
- Token aggregation depth is parameterized in `_aggregate_tokens`, allowing broader or narrower local context.

Current behavior tradeoff:

- More adaptive across heterogeneous graph shapes.
- Adds heuristic decisions, so its behavior is less transparent than the exact baseline.
- Sparse-mode quality depends strongly on token design and threshold calibration.

Best use case:

- Mixed datasets where some graphs are chain-like and others are relation-heavy.
- Cases where label and property context carries more signal than exact tree shape.

## 7. Behavioral Anchor Fusion

Implementation file:

- `algorithem_pipeline/algorithem_pipeline/algorithms/behavioral_anchor_fusion.py`

Purpose:

- This is the recommended best-option matcher for the current Sysmon attack-graph case.
- It is designed for both offline technique logs and future realtime stream logs where the observed attack tree can be incomplete, noisy, reordered, or slightly different from the stored attack tree.
- It intentionally combines graph matching with object-specific behavior matching and malicious-pattern evidence.

Why this algorithm fits this project best:

- Sysmon stream data often arrives as partial behavior rather than a complete final attack tree.
- The same MITRE technique can appear through multiple variants, tools, command lines, registry keys, process chains, or network/file side effects.
- Pure exact graph matching is too brittle for variants.
- Pure text/pattern matching is too shallow because it ignores causal structure.
- This matcher uses malicious patterns as high-confidence anchors, then checks whether the surrounding graph neighborhood behaves like the candidate technique.

High-level idea:

1. For each candidate technique, read its malicious and whitelist patterns from the pattern graph payload.
2. Scan the target graph nodes for malicious-pattern hits.
3. Treat hit nodes as suspicious anchors.
4. Expand a small neighborhood around those anchors.
5. Extract four evidence channels:
   - malicious-pattern coverage,
   - object/field tokens,
   - edge/relation semantics,
   - graph shape and local anchor context.
6. Fuse those channels into one score.
7. Return anchor-neighborhood node ids so the UI can highlight the suspicious region.

Evidence channels:

- `pattern_score`
  - Measures how many candidate malicious patterns appear in the target graph.
  - Uses both term coverage and number of suspicious nodes.
  - Whitelist matches subtract a small penalty, so common benign terms do not dominate.
- `anchor_score`
  - Compares the local neighborhood around suspicious target nodes with the candidate pattern's suspicious region.
  - This is the most important channel for realtime use because it can work even when the full graph is not complete yet.
- `object_score`
  - Compares object-specific tokens from nodes.
  - Includes node type, group, label, id, and node properties such as process image, command line, registry path, file path, event id, IP/port fields, or any normalized property available in the graph.
- `relation_score`
  - Compares edge semantics.
  - Uses edge type and typed triples such as `process>created>file` or `process>modified>registry`.
- `shape_score`
  - Compares coarse graph shape.
  - Uses node count bucket, edge count bucket, density bucket, node type degree buckets, and relation density.

Current fusion weights:

- supported `pattern_score`: 0.65
- `anchor_score`: 0.15
- `object_score`: 0.08
- `relation_score`: 0.07
- `shape_score`: 0.05

Additional gating:

- If a candidate has malicious patterns, the final score is gated by squared supported pattern evidence.
- `pattern_support` is based on how many malicious terms matched: one matched term is treated as weak support, two matched terms as medium support, and three or more as full support.
- This means strong graph similarity can still contribute, but techniques whose malicious indicators barely appear are much less likely to rank first.
- Whitelist pattern hits apply a limited penalty so noisy Sysmon/common-system tokens are dampened without completely hiding an attack chain.

How it uses malicious patterns:

- It does not only use patterns as a final yes/no condition.
- Patterns are used to locate suspicious anchor nodes first.
- Those anchors decide which neighborhood should receive more weight during object, relation, and structure comparison.
- The same matched anchor nodes are returned to the frontend as `matched_node_ids`, making the result explainable.

Realtime compatibility:

- The matcher does not require the whole attack tree to be complete.
- It can score a partial stream graph as soon as one or more suspicious anchors appear.
- Local anchor neighborhoods are robust to missing later events.
- Object tokens and relation triples tolerate attack variants better than exact subtree hash matching.
- If a stream graph grows over time, the score can be recomputed incrementally at window boundaries or on suspicious-event triggers.

Designed flexibility:

- `anchor_depth` controls how far from a suspicious node the algorithm looks.
- `_extract_patterns` supports pattern payloads from the existing `clean_attack_tree` format.
- `_term_matches_blob` supports both direct substring matching and token-based matching for longer terms.
- `_extract_features` can accept new Sysmon fields without changing the data model because it reads all node properties.
- Fusion weights are explicit and can be tuned after benchmark results.
- Whitelist penalty is capped, so it can reduce false positives without deleting useful evidence.

Accuracy and runtime balance:

- It is heavier than exact hashing but still practical because it uses counters and weighted Jaccard, not exhaustive graph isomorphism.
- Runtime is roughly proportional to candidate graph size plus pattern-term scanning cost.
- The expensive part is scanning terms across nodes for each candidate technique.
- If needed later, this can be optimized by caching node text blobs or building an inverted token index for realtime windows.

Expected strengths:

- Best overall fit for Sysmon attack behavior because it combines indicator evidence and graph evidence.
- Better than exact matching when attack variants change labels or add/remove events.
- Better than pure approximate tree matching when malicious command/registry/file/network indicators are highly discriminative.
- More explainable than generic similarity because highlighted nodes are anchored in malicious evidence.

Expected limitations:

- Quality depends on malicious pattern quality.
- If patterns are too broad, common system behavior can inflate scores.
- If patterns are missing for a technique, the algorithm falls back to behavior/graph similarity but loses its strongest anchor signal.
- Fusion weights should be benchmarked on real stream windows before being treated as final.

Best use case:

- Realtime Sysmon graph windows.
- Offline technique classification with noisy raw logs.
- Detecting variants of known MITRE techniques where malicious indicators and object behavior matter as much as exact tree shape.

## 8. Ranking And Evaluation

Relevant files:

- `algorithem_pipeline/algorithem_pipeline/evaluation/benchmark.py`
- `algorithem_pipeline/algorithem_pipeline/evaluation/metrics.py`

How results are used:

- Each matcher returns a `TechniqueMatch` with:
  - `algorithm`
  - `technique`
  - `score`
  - `runtime_ms`
  - `matched_node_ids`
  - `notes`
- The service sorts matches by score and returns top-k results.
- The UI uses `matched_node_ids` to highlight nodes in the graph.
- Top-1 accuracy is computed by checking whether the highest-ranked technique equals the target technique.

Important design choice:

- Scoring and explanation are returned together.
- That lets the frontend show not only ranking, but also which nodes were responsible for the match.

## 9. UI Reference For Node Rendering

If you want to reuse the graph display style from `inspect_log_gui`, the main reference files are:

- `inspect_log_gui/frontend/index.html`
  - Layout for technique selector, graph canvas, filter panel, and inspect panel.
- `inspect_log_gui/frontend/app.js`
  - Main graph rendering logic and interaction state.
- `inspect_log_gui/frontend/styles.css`
  - Visual system for the graph canvas and side panels.

What that UI is already doing:

- Renders graph nodes and edges in the frontend.
- Supports zoom and pan.
- Keeps a `fullGraph`, `filteredGraph`, and `displayGraph` model.
- Supports grouped-by-GUID view versus raw event-node view.
- Supports click-to-inspect behavior and temporary highlighting.

The current `algorithem_pipeline` frontend is simpler and implemented here:

- `algorithem_pipeline/frontend/index.html`
- `algorithem_pipeline/frontend/app.js`
- `algorithem_pipeline/frontend/styles.css`

Main difference:

- `inspect_log_gui` is the richer node-inspection UI reference.
- `algorithem_pipeline` currently focuses on algorithm result ranking and matched-node highlighting.

## 10. Practical Tuning Guidance

If you want to tune behavior later, the best first edit points are:

- Strict exactness:
  - `baseline_exact.py` -> `_node_signature`
- Approximate tolerance:
  - `core_approximate.py` -> `_node_cost`, `threshold`, `missing_ratio_k`
- Large-catalog throughput:
  - `scale_multipattern.py` -> `_compact_signature`, cache policy
- Sparse contextual sensitivity:
  - `structure_adaptive.py` -> `_tokenize`, `_aggregate_tokens`, dense threshold, weighted Jaccard cutoff
- Realtime behavioral fusion:
  - `behavioral_anchor_fusion.py` -> `anchor_depth`, fusion weights, `_term_matches_blob`, whitelist penalty, object/relation token extraction

## 11. Recommended Reading Order

If you want to understand the system from top to bottom, read in this order:

1. `algorithem_pipeline/algorithem_pipeline/models.py`
2. `algorithem_pipeline/algorithem_pipeline/io/tree_adapter.py`
3. `algorithem_pipeline/algorithem_pipeline/algorithms/base.py`
4. `algorithem_pipeline/algorithem_pipeline/algorithms/baseline_exact.py`
5. `algorithem_pipeline/algorithem_pipeline/algorithms/core_approximate.py`
6. `algorithem_pipeline/algorithem_pipeline/algorithms/scale_multipattern.py`
7. `algorithem_pipeline/algorithem_pipeline/algorithms/structure_adaptive.py`
8. `algorithem_pipeline/algorithem_pipeline/algorithms/behavioral_anchor_fusion.py`
9. `algorithem_pipeline/algorithem_pipeline/service/matcher_service.py`
10. `algorithem_pipeline/frontend/app.js`

That sequence follows the real execution path closely enough to debug or extend the system without getting lost in UI details too early.