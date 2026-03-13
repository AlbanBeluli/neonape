from neon_ape.commands.interactive import _ask_text


class StubConsole:
    def __init__(self, response: str) -> None:
        self.response = response

    def input(self, prompt: str) -> str:
        return self.response


def test_ask_text_returns_none_for_back() -> None:
    console = StubConsole("b")
    assert _ask_text(console, "Target") is None


def test_ask_text_uses_default_when_empty() -> None:
    console = StubConsole("")
    assert _ask_text(console, "Limit", default="20") == "20"
