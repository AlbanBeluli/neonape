from neon_ape.commands.tools import _default_batch_history_target


def test_default_batch_history_target_prefers_workflow_name() -> None:
    label = _default_batch_history_target("httpx", "stoic.ee_workflow_httpx", ["www.stoic.ee", "ops.stoic.ee"])
    assert label == "batch:httpx:stoic.ee_workflow_httpx"


def test_default_batch_history_target_uses_count_for_multi_target_batch() -> None:
    label = _default_batch_history_target("naabu", None, ["www.stoic.ee", "ops.stoic.ee"])
    assert label == "batch:naabu:2_targets"
