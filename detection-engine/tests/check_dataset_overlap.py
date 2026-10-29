import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.dataset import get_benign_training_samples, get_expanded_evaluation_dataset, get_unseen_evaluation_dataset

train_samples = get_benign_training_samples(1000)
train_keys = set((s['method'], s['url']) for s in train_samples)

print("=" * 60)
print("  DATASET OVERLAP & GENERALIZATION VERIFICATION (Phase 8.1)")
print("=" * 60)

# Check Phase 7 holdout
holdout_v2, labels_v2 = get_expanded_evaluation_dataset()
v2_keys = set((s['method'], s['url']) for s in holdout_v2)
overlap_v2 = train_keys.intersection(v2_keys)
print(f"Holdout v2 (Phase 7): Total={len(holdout_v2)}, Overlap with train paths={len(overlap_v2)}")

# Check Phase 8 unseen holdout
holdout_v3, labels_v3 = get_unseen_evaluation_dataset()
v3_keys = set((s['method'], s['url']) for s in holdout_v3)
overlap_v3 = train_keys.intersection(v3_keys)
print(f"Holdout v3 (Phase 8 Unseen): Total={len(holdout_v3)}, Overlap with train paths={len(overlap_v3)}")
for o in overlap_v3:
    print(f"  v3 Overlap: {o}")
print("=" * 60)
