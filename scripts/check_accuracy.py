import pandas as pd
import sys
import os

sys.stdout.reconfigure(encoding='utf-8')

agent_file = 'sample_agent_output.csv'
truth_file = 'dataset/sample_output.csv'

if not os.path.exists(agent_file):
    print(f"ERROR: {agent_file} not found. Run the agent first.")
    sys.exit(1)

if not os.path.exists(truth_file):
    print(f"ERROR: {truth_file} not found.")
    sys.exit(1)

agent = pd.read_csv(agent_file, dtype=str, keep_default_na=False)
truth = pd.read_csv(truth_file, dtype=str, keep_default_na=False)

# Normalize column names
agent.columns = [c.strip().lower() for c in agent.columns]
truth.columns = [c.strip().lower() for c in truth.columns]

print(f"Agent columns: {list(agent.columns)}")
print(f"Truth columns: {list(truth.columns)}")
print(f"Agent rows: {len(agent)}, Truth rows: {len(truth)}")

merged = truth.merge(agent, on='case_id', suffixes=('_truth', '_agent'))
merged['status_match'] = merged['deletion_status_truth'].str.strip() == merged['deletion_status_agent'].str.strip()

correct = merged['status_match'].sum()
total = len(merged)
accuracy = (correct / total) * 100 if total > 0 else 0

print(f"\n{'='*65}")
print(f"  ACCURACY ON {total} SAMPLE CASES: {correct}/{total} = {accuracy:.1f}%")
print(f"{'='*65}\n")

print(f"{'Case':<10} {'Ground Truth':<20} {'Agent Output':<20} {'Match'}")
print('-' * 65)
for _, row in merged.iterrows():
    mark = 'PASS' if row['status_match'] else 'FAIL'
    print(f"{row['case_id']:<10} {row['deletion_status_truth']:<20} {row['deletion_status_agent']:<20} {mark}")

mismatches = merged[~merged['status_match']]
if not mismatches.empty:
    print(f"\nMISMATCHED CASES ({len(mismatches)}):")
    for _, row in mismatches.iterrows():
        print(f"  {row['case_id']}: expected '{row['deletion_status_truth']}', got '{row['deletion_status_agent']}'")
else:
    print("\nAll cases matched perfectly!")

# Distribution
print(f"\nAgent status distribution:")
print(agent['deletion_status'].value_counts().to_string())
print(f"\nGround truth distribution:")
print(truth['deletion_status'].value_counts().to_string())
