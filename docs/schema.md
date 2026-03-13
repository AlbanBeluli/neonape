# Schema Design

## Storage Strategy

SQLite is the local system of record. Sensitive values such as notes containing credentials, API keys, or investigator comments are encrypted at the application layer before insertion.

Full-database SQLCipher support can be added later if the target machine provides it, but the MVP should not block on that dependency.

## Tables

### `checklists`

- `id`: integer primary key
- `slug`: unique text identifier
- `title`: display name
- `description`: phase summary
- `created_at`: timestamp

### `checklist_items`

- `id`: integer primary key
- `checklist_id`: foreign key
- `step_order`: integer
- `section_name`: themed grouping
- `title`: item title
- `guide_text`: step-by-step guidance
- `example_command`: lab-safe sample syntax
- `status`: pending, in_progress, complete, skipped
- `completed_at`: timestamp nullable

### `scan_runs`

- `id`: integer primary key
- `tool_name`: nmap, whois, dns
- `target`: validated target string
- `command_line`: normalized rendered command
- `status`: success, failed, partial
- `raw_output_path`: optional local XML or JSONL artifact path
- `started_at`: timestamp
- `finished_at`: timestamp nullable

### `scan_findings`

- `id`: integer primary key
- `scan_run_id`: foreign key
- `finding_type`: host, port, service, dns_record, note
- `key`: normalized label
- `value`: normalized value
- `metadata_json`: compact JSON string

### `notes`

- `id`: integer primary key
- `target`: nullable target string
- `title`: short title
- `ciphertext`: encrypted content blob
- `created_at`: timestamp
- `updated_at`: timestamp

### `tool_history`

- `id`: integer primary key
- `tool_name`: wrapper name
- `target`: nullable target
- `arguments_json`: serialized argument list
- `exit_code`: integer
- `created_at`: timestamp

### `secrets`

- `id`: integer primary key
- `secret_name`: unique logical name
- `ciphertext`: encrypted secret blob
- `created_at`: timestamp
- `updated_at`: timestamp

## Indexes

- unique index on `checklists.slug`
- index on `scan_runs.target`
- index on `scan_findings.scan_run_id`
- index on `checklist_items.checklist_id, step_order`

## Query Rules

- Use parameterized statements only
- Never store plaintext secrets
- Store rendered commands only after normalization and redaction
