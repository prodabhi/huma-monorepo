#!/usr/bin/env python3
"""Phase B: a gradient-boosted classifier on the sessions the report exported (features.csv), calibrated with isotonic
regression, written as detection/model.json for model.mjs to evaluate. Run from frontend/ once enough labelled, recorded
sessions exist (the synthetic rows are excluded unless --with-synthetic; they are a model, not data):

    python3 detection/eval/train.py [--with-synthetic] [--min-sessions 200]

Needs lightgbm and scikit-learn (pip install lightgbm scikit-learn). The rule ensemble stays the hard override for
traps and integrity (score.mjs); this model only replaces the feature logit.
"""
import argparse, csv, json, math, os, sys
from datetime import datetime, timezone

here = os.path.dirname(os.path.abspath(__file__))
parser = argparse.ArgumentParser()
parser.add_argument('--with-synthetic', action='store_true')
parser.add_argument('--min-sessions', type=int, default=200)
parser.add_argument('--out', default=os.path.join(here, '..', 'model.json'))
args = parser.parse_args()

rows = list(csv.DictReader(open(os.path.join(here, 'features.csv'))))
rows = [r for r in rows if args.with_synthetic or r['synthetic'] == '0']
names = [k for k in rows[0].keys() if k not in ('human', 'generator', 'modality', 'synthetic', 'integrity_pass')] if rows else []
if len(rows) < args.min_sessions or len({r['human'] for r in rows}) < 2:
    print(f'Not training: {len(rows)} usable sessions ({sum(r["human"] == "1" for r in rows)} human); need {args.min_sessions} with both labels.')
    sys.exit(0)
try:
    import numpy as np, lightgbm as lgb
    from sklearn.isotonic import IsotonicRegression
    from sklearn.model_selection import StratifiedKFold
except ImportError as error:
    print('Missing', error.name, ': pip install lightgbm scikit-learn'); sys.exit(1)

X = np.array([[float(r[n]) if r[n] != '' else np.nan for n in names] for r in rows]); y = np.array([int(r['human']) for r in rows])
params = dict(objective='binary', learning_rate=0.05, num_leaves=15, min_data_in_leaf=10, feature_fraction=0.8, bagging_fraction=0.8, bagging_freq=1, verbose=-1)
# Out-of-fold scores for the calibration, so the isotonic map never sees a session's own training fit.
oof = np.zeros(len(y))
for train, test in StratifiedKFold(5, shuffle=True, random_state=1).split(X, y):
    booster = lgb.train(params, lgb.Dataset(X[train], y[train]), num_boost_round=300)
    oof[test] = booster.predict(X[test])
iso = IsotonicRegression(out_of_bounds='clip').fit(oof, y)
final = lgb.train(params, lgb.Dataset(X, y), num_boost_round=300)
dump = final.dump_model()
# A piecewise-linear calibration map model.mjs can apply.
xs = np.linspace(0, 1, 101); ys = iso.predict(xs)
model = {'version': 'gbdt-' + datetime.now(timezone.utc).strftime('%Y-%m-%d'), 'features': names, 'trees': dump['tree_info'],
         'calibration': {'x': [float(v) for v in xs], 'y': [float(v) for v in ys]}, 'sessions': len(rows), 'human': int(y.sum())}
json.dump(model, open(args.out, 'w'))
auc = None
try:
    from sklearn.metrics import roc_auc_score; auc = roc_auc_score(y, oof)
except Exception: pass
print(f'Wrote {args.out}: {len(rows)} sessions, {len(names)} features, out-of-fold AUC {auc}')
