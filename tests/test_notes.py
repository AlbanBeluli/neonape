import sqlite3
from pathlib import Path

from neon_ape.commands.notes import run_add_note
from neon_ape.db.repository import get_note, initialize_database, list_note_headers


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    return connection


def test_add_note_stores_encrypted_payload(console=None) -> None:
    root = Path(__file__).resolve().parents[1]
    connection = _connection()
    initialize_database(connection, root / "neon_ape" / "db" / "schema.sql")

    class StubConsole:
        def print(self, *args, **kwargs):
            return None

    note_id = run_add_note(
        StubConsole(),
        connection,
        passphrase="secret-pass",
        title="Panel",
        body="Observed admin panel",
        target="app.example.com",
    )
    note = get_note(connection, note_id)
    headers = list_note_headers(connection)

    assert note is not None
    assert bytes(note["ciphertext"]) != b"Observed admin panel"
    assert headers[0]["title"] == "Panel"
    assert headers[0]["target"] == "app.example.com"
