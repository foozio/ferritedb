import os
import re
import json
import uuid
import glob

BEADS_ISSUES_FILE = ".beads/issues.jsonl"
CONDUCTOR_DIR = "conductor"
TRACKS_FILE = os.path.join(CONDUCTOR_DIR, "tracks.md")

def parse_tracks():
    tracks = []
    if not os.path.exists(TRACKS_FILE):
        print(f"No tracks file found at {TRACKS_FILE}")
        return tracks

    with open(TRACKS_FILE, 'r') as f:
        content = f.read()
    
    # Regex to find track links: *Link: [./conductor/tracks/telemetry_20251228/](./conductor/tracks/telemetry_20251228/)*
    # and names: ## [~] Track: Implement a centralized telemetry and metrics system
    
    # Simple approach: find directories in conductor/tracks/
    tracks_dir = os.path.join(CONDUCTOR_DIR, "tracks")
    if not os.path.exists(tracks_dir):
        return tracks

    for track_id in os.listdir(tracks_dir):
        plan_path = os.path.join(tracks_dir, track_id, "plan.md")
        if os.path.exists(plan_path):
            tracks.append({
                "id": track_id,
                "plan_path": plan_path
            })
    return tracks

def parse_plan(plan_path):
    tasks = []
    with open(plan_path, 'r') as f:
        lines = f.readlines()

    current_phase = "General"
    
    for line in lines:
        line = line.strip()
        if line.startswith("## Phase"):
            current_phase = line.strip("# ").strip()
        
        # Match tasks: - [ ] Task: ... or - [x] Task: ...
        match = re.match(r'- \[(x| )\].*Task: (.+)', line)
        if match:
            status_char = match.group(1)
            description = match.group(2)
            status = "done" if status_char == 'x' else "todo"
            tasks.append({
                "description": description,
                "status": status,
                "phase": current_phase
            })
    return tasks

def generate_issues(tracks):
    issues = []
    
    for track in tracks:
        tasks = parse_plan(track["plan_path"])
        track_id = track["id"]
        
        previous_task_id = None
        
        for i, task in enumerate(tasks):
            # Deterministic ID for idempotency (simple hash of track + index)
            # In a real sync, we might want to store this ID in the plan.md
            issue_id = f"{track_id}-{i}"
            
            issue = {
                "id": issue_id,
                "title": task["description"],
                "status": task["status"],
                "labels": [track_id, task["phase"]],
                "links": [] # Dependencies
            }
            
            # Chain dependencies: Task 0 blocks Task 1 (Task 1 depends on Task 0)
            # In beads/graph terms, often we express "blocks".
            # Let's assume a "blocks" relationship or "depends_on".
            # I'll add a 'blocks' field if I'm the previous task blocking the current one.
            # Or 'deps' field. Let's use a generic 'links' for now or try to infer standard fields.
            # Given the lack of explicit schema, I'll use "blocked_by": [prev_id]
            
            if previous_task_id:
                issue["blocked_by"] = [previous_task_id]
            
            issues.append(issue)
            previous_task_id = issue_id
            
    return issues

def write_beads(issues):
    # Ensure directory exists
    os.makedirs(os.path.dirname(BEADS_ISSUES_FILE), exist_ok=True)
    
    with open(BEADS_ISSUES_FILE, 'w') as f:
        for issue in issues:
            f.write(json.dumps(issue) + "\n")
    print(f"Exported {len(issues)} issues to {BEADS_ISSUES_FILE}")

def main():
    tracks = parse_tracks()
    issues = generate_issues(tracks)
    write_beads(issues)

if __name__ == "__main__":
    main()
