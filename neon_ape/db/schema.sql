CREATE TABLE IF NOT EXISTS checklists (
    id INTEGER PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS checklist_items (
    id INTEGER PRIMARY KEY,
    checklist_id INTEGER NOT NULL,
    step_order INTEGER NOT NULL,
    section_name TEXT NOT NULL,
    title TEXT NOT NULL,
    guide_text TEXT NOT NULL,
    example_command TEXT NOT NULL,
    action_tool TEXT,
    action_profile TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    completed_at TEXT,
    FOREIGN KEY (checklist_id) REFERENCES checklists(id)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY,
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL,
    command_line TEXT NOT NULL,
    status TEXT NOT NULL,
    raw_output_path TEXT,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id INTEGER PRIMARY KEY,
    scan_run_id INTEGER NOT NULL,
    finding_type TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    target TEXT,
    title TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tool_history (
    id INTEGER PRIMARY KEY,
    tool_name TEXT NOT NULL,
    target TEXT,
    arguments_json TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY,
    secret_name TEXT NOT NULL UNIQUE,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_checklist_items_order
ON checklist_items (checklist_id, step_order);

CREATE INDEX IF NOT EXISTS idx_scan_runs_target
ON scan_runs (target);

CREATE INDEX IF NOT EXISTS idx_scan_findings_run
ON scan_findings (scan_run_id);
