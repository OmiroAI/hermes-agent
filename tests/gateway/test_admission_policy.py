"""Required admission command: real child processes and gateway entry points."""
import asyncio
import json
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest

from gateway import admission_policy as policy

SOURCE = {"platform": "telegram", "user_id": "test-user", "chat_id": "test-chat", "chat_type": "private"}


def command(monkeypatch, code, timeout=5):
    monkeypatch.setattr(policy, "_settings", lambda: {"command": [sys.executable, "-c", code], "timeout_seconds": timeout})


@pytest.mark.asyncio
async def test_disabled_and_explicit_allow(monkeypatch):
    monkeypatch.setattr(policy, "_settings", lambda: None)
    assert (await policy.admit_gateway_event("message", SOURCE)).allow
    command(monkeypatch, 'import json,sys; f=json.load(sys.stdin); assert f["source"]["user_id"]=="test-user"; print(json.dumps({"decision":"allow"}))')
    assert (await policy.admit_gateway_event("message", SOURCE, text="untrusted")).allow


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [
    'print("null")', 'print("{}")', 'print("broken")', 'raise RuntimeError("failure")',
    'print(\'{"decision":"allow","reply":"unexpected"}\')',
    'print(\'{"decision":"deny","reply":false}\')', 'print("x" * 262145)',
])
async def test_invalid_and_error_verdicts_deny(monkeypatch, code):
    command(monkeypatch, code)
    result = await policy.admit_gateway_event("message", SOURCE)
    assert not result.allow and result.reply == policy.PAUSED


@pytest.mark.asyncio
async def test_missing_command_and_timeout_deny(monkeypatch):
    monkeypatch.setattr(policy, "_settings", lambda: {"command": ["/nonexistent-policy-command"]})
    assert not (await policy.admit_gateway_event("message", SOURCE)).allow
    command(monkeypatch, 'import sys; sys.stdin.read(); import threading; threading.Event().wait()', timeout=0.05)
    assert not (await policy.admit_gateway_event("message", SOURCE)).allow


@pytest.mark.asyncio
async def test_denial_reply_only_for_messages(monkeypatch):
    command(monkeypatch, 'print(\'{"decision":"deny","reply":"paused"}\')')
    assert (await policy.admit_gateway_event("message", SOURCE)).reply == "paused"
    for kind in ("callback", "reaction", "platform_event"):
        result = await policy.admit_gateway_event(kind, SOURCE)
        assert not result.allow and result.reply is None


@pytest.mark.asyncio
async def test_config_parse_failure_denies(tmp_path, monkeypatch):
    from hermes_cli import config
    path = tmp_path / "config.yaml"
    path.write_text("gateway: [invalid")
    monkeypatch.setattr(config, "get_config_path", lambda: path)
    assert not (await policy.admit_gateway_event("message", SOURCE)).allow


@pytest.mark.asyncio
async def test_inbound_and_busy_stop_before_privileged_dispatch(monkeypatch):
    from gateway.run_inbound import GatewayInboundMixin
    from gateway.run_busy import GatewayBusySessionMixin
    monkeypatch.setattr(policy, "admit_gateway_event", AsyncMock(return_value=policy.AdmissionDecision(False)))
    # Real ingress methods; no session store, commands, memory or agent on this runner.
    # A fallthrough therefore fails, rather than silently exercising a mocked downstream.
    runner = SimpleNamespace(config=None, _scale_to_zero_note_real_inbound=lambda: None)
    event = SimpleNamespace(source=SimpleNamespace(**SOURCE), internal=False, text="/approve", message_id="test")
    assert await GatewayInboundMixin._hm_admit_event(runner, event) is None
    assert await GatewayBusySessionMixin._handle_active_session_busy_message(runner, event, "test-session") is True


@pytest.mark.asyncio
async def test_control_hooks_stop_before_dispatch(monkeypatch):
    from gateway.run_adapters import GatewayAdapterLifecycleMixin
    monkeypatch.setattr(policy, "admit_gateway_event", AsyncMock(return_value=policy.AdmissionDecision(False)))
    runner = SimpleNamespace()
    await GatewayAdapterLifecycleMixin._handle_reaction_event(runner, SOURCE)
    await GatewayAdapterLifecycleMixin._handle_gateway_platform_event(runner, {}, SOURCE)


@pytest.mark.asyncio
async def test_cancellation_terminates_command(monkeypatch, tmp_path):
    pid_file = tmp_path / "pid"
    code = 'import os,pathlib,sys,threading; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); threading.Event().wait()'
    monkeypatch.setattr(policy, "_settings", lambda: {"command": [sys.executable, "-c", code, str(pid_file)]})
    task = asyncio.create_task(policy.admit_gateway_event("message", SOURCE))
    from tests.waiting import async_wait_until
    await async_wait_until(pid_file.exists, timeout=5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    import psutil
    assert not psutil.pid_exists(int(pid_file.read_text()))


@pytest.mark.asyncio
async def test_producer_denial_stops_before_hooks_and_admission(monkeypatch):
    from contextlib import asynccontextmanager
    from gateway.platforms import webhook_ingress
    monkeypatch.setattr(policy, "admit_gateway_event", AsyncMock(return_value=policy.AdmissionDecision(False, "paused")))
    @asynccontextmanager
    async def scope(adapter, event):
        yield SimpleNamespace(runner=SimpleNamespace(config=None))
    monkeypatch.setattr(webhook_ingress, "producer_scope", scope)
    event = SimpleNamespace(source=SOURCE, text="/approve", message_id="test-producer")
    assert await webhook_ingress.admit_producer(None, event) is None
    assert event._consumer_reply == "paused"


@pytest.mark.asyncio
async def test_telegram_callback_denial_stops_before_controls(monkeypatch):
    from plugins.platforms.telegram.adapter import TelegramAdapter
    monkeypatch.setattr(policy, "admit_gateway_event", AsyncMock(return_value=policy.AdmissionDecision(False)))
    query = SimpleNamespace(from_user=SimpleNamespace(id="test-user"), answer=AsyncMock())
    runner = SimpleNamespace(_callback_ctx=lambda query: {"chat_id": "test-chat", "chat_type": "private"})
    await TelegramAdapter._handle_callback_query(runner, SimpleNamespace(callback_query=query), None)
    query.answer.assert_awaited_once()


@pytest.mark.asyncio
async def test_policy_configuration_is_profile_scoped(tmp_path):
    from hermes_constants import set_hermes_home_override, reset_hermes_home_override
    import hermes_yaml as yaml
    for name, verdict in (("owner-profile", "allow"), ("external-profile", "deny")):
        home = tmp_path / name
        home.mkdir()
        code = 'import json; print(json.dumps({"decision": "' + verdict + '"}))'
        (home / "config.yaml").write_text(yaml.safe_dump({"gateway": {"admission_policy": {
            "command": [sys.executable, "-c", code], "timeout_seconds": 5}}}))
        token = set_hermes_home_override(str(home))
        try:
            assert (await policy.admit_gateway_event("message", SOURCE)).allow == (verdict == "allow")
        finally:
            reset_hermes_home_override(token)


@pytest.mark.asyncio
async def test_consumed_message_reply_keeps_thread_and_does_not_fall_through(monkeypatch):
    from gateway.run_inbound import GatewayInboundMixin
    from gateway.run_busy import GatewayBusySessionMixin
    monkeypatch.setattr(policy, "admit_gateway_event", AsyncMock(return_value=policy.AdmissionDecision(False, "scoped result")))
    adapter = SimpleNamespace(send=AsyncMock())
    runner = SimpleNamespace(config=None, _delivery_adapter_for=lambda source: adapter,
        _thread_metadata_for_source=lambda source, message: {"thread_id": "test-thread", "reply_to": message})
    event = SimpleNamespace(source=SimpleNamespace(**SOURCE), internal=False, text="request", message_id="test-message")
    assert await GatewayInboundMixin._hm_admit_event(runner, event) is None
    adapter.send.assert_awaited_once_with("test-chat", "scoped result", metadata={"thread_id": "test-thread", "reply_to": "test-message"})
    adapter.send.reset_mock()
    assert await GatewayBusySessionMixin._handle_active_session_busy_message(runner, event, "test-session")
    adapter.send.assert_awaited_once_with("test-chat", "scoped result", metadata={"thread_id": "test-thread", "reply_to": "test-message"})


@pytest.mark.asyncio
@pytest.mark.platforms("posix")
async def test_timeout_terminates_policy_descendants(monkeypatch, tmp_path):
    import psutil
    pid_file = tmp_path / "descendant"
    code = ('import subprocess,sys,pathlib,threading; '
            'child=subprocess.Popen([sys.executable,"-c","import threading;threading.Event().wait()"]); '
            'pathlib.Path(sys.argv[1]).write_text(str(child.pid)); threading.Event().wait()')
    monkeypatch.setattr(policy, "_settings", lambda: {
        "command": [sys.executable, "-c", code, str(pid_file)], "timeout_seconds": 2})
    result = await policy.admit_gateway_event("message", SOURCE)
    assert not result.allow
    child = int(pid_file.read_text())
    def terminated():
        try:
            return psutil.Process(child).status() == psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return True
    from tests.waiting import async_wait_until
    await async_wait_until(terminated, timeout=5)
