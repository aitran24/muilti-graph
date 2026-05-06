# Algorithm Details

This document explains each implemented algorithm and how it is evaluated.

## 1) Baseline Exact

File: `algorithem_pipeline/algorithms/baseline_exact.py`

- Goal: strict exact recall baseline.
- Method:
  - Convert graph to rooted forest (`HAS_ROOT` aware).
  - Build canonical subtree hash for every node using node signature + sorted child hashes.
  - Pattern root is matched only if canonical hash appears exactly in target subtrees.
- Strength:
  - Deterministic and interpretable.
  - Useful upper bound for clean exact structures.
- Limitation:
  - Brittle under noise, missing nodes, or label variants.

## 2) Core Approximate

File: `algorithem_pipeline/algorithms/core_approximate.py`

- Goal: robust to noisy or partially missing structures.
- Method:
  - Tree edit-distance style score with node substitution cost and child assignment cost.
  - Similarity:
    - `similarity = 1 - distance / max(size_target, size_pattern)`
  - Match policy:
    - accept if `similarity >= theta` or missing ratio `<= k`.
- Default thresholds:
  - `theta = 0.65`
  - `k = 0.35`
- Strength:
  - Handles partial matches and topology drift.
- Limitation:
  - More expensive than exact hashing.

## 3) Scale Multi-Pattern

File: `algorithem_pipeline/algorithms/scale_multipattern.py`

- Goal: evaluate many patterns in one traversal.
- Method:
  - Compile each pattern into subtree hash set.
  - Traverse target once to compute subtree hashes for all nodes.
  - Hit = intersection between target hashes and compiled pattern hashes.
- Strength:
  - Fast reuse when pattern catalog is large.
  - Suitable for multi-technique detection in a single pass.
- Limitation:
  - Hashing is exact on signature, so semantic variants are not captured.

## 4) Structure Adaptive

File: `algorithem_pipeline/algorithms/structure_adaptive.py`

- Goal: adapt strategy to graph structure (sparse vs dense).
- Method:
  - Compute relation density `|E_relation| / |V|`.
  - If sparse:
    - Weighted contextual token matching around local subtree neighborhoods.
  - If dense:
    - Fallback to approximate matcher configuration.
- Strength:
  - More stable across different graph topologies.
  - Allows lightweight context-aware scoring on sparse DAG-like data.
- Limitation:
  - Requires threshold tuning for each dataset.

## 5) Behavioral Anchor Fusion

File: `algorithem_pipeline/algorithms/behavioral_anchor_fusion.py`

- Goal: best-fit matcher for this Sysmon case, especially realtime streams with incomplete or variant attack trees.
- Method:
  - Use malicious patterns from each technique as suspicious anchors.
  - Expand local graph neighborhoods around matched anchors.
  - Compare target and pattern with five evidence channels: supported malicious-pattern coverage, anchor context, object/property tokens, edge semantics, and graph shape.
  - Apply nonlinear pattern gating so generic structural similarity cannot easily outrank strong malicious-pattern coverage.
- Strength:
  - Combines graph matching and behavior/object matching.
  - Works better with attack variants than exact subtree matching.
  - Returns matched anchor neighborhoods for explainable UI highlighting.
  - Designed to be compatible with future realtime Sysmon windows.
- Limitation:
  - Depends on malicious pattern quality.
  - Heavier than exact hashing because it scans node text and extracts multiple feature channels.

## Comparison Metrics

Implemented in `algorithem_pipeline/evaluation/`:

- `runtime_ms`: cumulative runtime per algorithm for all techniques.
- `top1_technique`: highest score technique prediction.
- `top1_score`: confidence score for top result.
- `accuracy`: top-1 exact hit against target graph `technique` field.

## UI Interaction Mapping

- Run all selected algorithms on one target graph.
- Display ranked techniques per algorithm.
- Click one technique to:
  - highlight matched node ids,
  - dim unrelated nodes/edges (prune-like focus view).
