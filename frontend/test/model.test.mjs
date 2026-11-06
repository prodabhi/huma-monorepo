import test from 'node:test';
import assert from 'node:assert/strict';
import { treeValue, modelProbability } from '../detection/model.mjs';

// A tiny model in LightGBM's dump shape: one tree on rollover_rate (missing goes left), one on word_onset_ratio.
const model = { version: 'test', features: ['rollover_rate', 'word_onset_ratio'],
  trees: [{ tree_structure: { split_feature: 0, threshold: 0.05, decision_type: '<=', default_left: true, left_child: { leaf_value: -1.5 }, right_child: { leaf_value: 1.5 } } },
    { tree_structure: { split_feature: 1, threshold: 1.3, decision_type: '<=', default_left: false, left_child: { leaf_value: -1 }, right_child: { leaf_value: 1 } } }],
  calibration: { x: [0, 0.5, 1], y: [0.05, 0.4, 0.95] } };

test('the trees route on thresholds and missing values, and the calibration maps the sum to a probability', () => {
  assert.equal(treeValue(model.trees[0].tree_structure, [0.1, null]), 1.5);
  assert.equal(treeValue(model.trees[0].tree_structure, [0.01, null]), -1.5);
  assert.equal(treeValue(model.trees[0].tree_structure, [null, null]), -1.5); // missing: default left
  assert.equal(treeValue(model.trees[1].tree_structure, [null, null]), 1); // missing: default right
  const human = modelProbability(model, { rollover_rate: 0.12, word_onset_ratio: 1.9 }), bot = modelProbability(model, { rollover_rate: 0, word_onset_ratio: 1.0 });
  assert.ok(human > 0.8 && bot < 0.2, JSON.stringify([human, bot]));
  const middle = modelProbability(model, { rollover_rate: 0.12, word_onset_ratio: 1.0 }); // sum 0.5: p ≈ 0.62
  assert.ok(middle > 0.4 && middle < 0.7, String(middle));
  assert.ok(modelProbability(model, {}) >= 0.01);
});
