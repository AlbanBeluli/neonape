APP_TITLE = "Neon Ape"

PALETTE = {
    "accent": "bold bright_magenta",
    "green": "bold bright_green",
    "orange": "bold bright_yellow",
    "red": "bold bright_red",
    "ember": "bold orange3",
}


def section_style(name: str) -> str:
    return PALETTE.get(name, "bold white")
