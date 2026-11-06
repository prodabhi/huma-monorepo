// Phase B: a gradient-boosted model (LightGBM, trained by eval/train.py and dumped as model.json) evaluated here, with
// its isotonic calibration. Unused until a model is trained on recorded sessions; score.mjs keeps the rule ensemble
// as the hard override for traps and integrity either way.
import { clamp } from './stats.mjs';

/** One LightGBM tree (its dump format) applied to a feature row; missing values follow each node's default branch. */
export function treeValue(node, row) {
  while (node.split_feature !== undefined) {
    const value = row[node.split_feature], missing = value === null || value === undefined || Number.isNaN(value);
    const left = missing ? node.default_left !== false : node.decision_type === '<=' ? value <= node.threshold : value < node.threshold;
    node = left ? node.left_child : node.right_child;
  }
  return node.leaf_value;
}
/** The model's calibrated probability that a person typed the session, from feature values by name. */
export function modelProbability(model, values) {
  const row = model.features.map(name => values[name] ?? null);
  let raw = 0;
  for (const tree of model.trees) raw += treeValue(tree.tree_structure, row);
  const p = 1 / (1 + Math.exp(-raw)), { x, y } = model.calibration;
  // Piecewise-linear calibration.
  let i = 0; while (i < x.length - 2 && x[i + 1] < p) i++;
  const u = x[i + 1] === x[i] ? 0 : (p - x[i]) / (x[i + 1] - x[i]);
  return clamp(y[i] + (y[i + 1] - y[i]) * u, 0.01, 0.99);
}
