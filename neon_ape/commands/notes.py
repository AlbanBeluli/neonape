from __future__ import annotations

import base64

from cryptography.fernet import InvalidToken
from rich.console import Console
from rich.panel import Panel

from neon_ape.db.repository import get_note, list_note_headers, store_note
from neon_ape.services.crypto import decrypt_text, derive_key, encrypt_text, new_salt
from neon_ape.ui.theme import section_style
from neon_ape.ui.views import build_notes_table


def run_add_note(
    console: Console,
    connection,
    *,
    passphrase: str,
    title: str,
    body: str,
    target: str | None = None,
) -> int:
    salt = new_salt()
    key = derive_key(passphrase, salt)
    ciphertext = encrypt_text(body, key)
    payload = base64.urlsafe_b64encode(salt + ciphertext)
    note_id = store_note(connection, target=target, title=title, ciphertext=payload)
    console.print(f"[bold green]Stored encrypted note #{note_id}[/bold green]")
    return note_id


def run_list_notes(console: Console, notes: list[dict[str, str | int | None]]) -> None:
    console.print(build_notes_table(notes))


def run_view_note(console: Console, connection, *, passphrase: str, note_id: int) -> bool:
    note = get_note(connection, note_id)
    if note is None:
        console.print(f"[bold red]Note {note_id} was not found.[/bold red]")
        return False
    raw = base64.urlsafe_b64decode(bytes(note["ciphertext"]))
    salt = raw[:16]
    ciphertext = raw[16:]
    key = derive_key(passphrase, salt)
    try:
        plaintext = decrypt_text(ciphertext, key)
    except InvalidToken:
        console.print("[bold red]Unable to decrypt note. Check the passphrase.[/bold red]")
        return False
    console.print(
        Panel.fit(
            f"[bold]ID:[/bold] {note['id']}\n"
            f"[bold]Target:[/bold] {note.get('target') or '-'}\n"
            f"[bold]Title:[/bold] {note['title']}\n"
            f"[bold]Body:[/bold]\n{plaintext}",
            title="Encrypted Note",
            style=section_style("accent"),
        )
    )
    return True


def run_notes_listing(console: Console, connection, *, target: str | None = None) -> None:
    notes = list_note_headers(connection, target=target)
    run_list_notes(console, notes)
