"""Opt-in external admission policy. A configured policy must explicitly allow ingress.

This is an application routing gate, not isolation from an operator's agent/tools.
The command is operator configuration; no message field is executable configuration.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import signal
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)
MAX_FRAME = 262144
PAUSED = "The admission service did not return a verified result. Work is paused; check request status before retrying."


@dataclass(frozen=True)
class AdmissionDecision:
    allow: bool
    reply: str | None = None


def _settings() -> Any:
    from hermes_cli.config import get_config_path, load_config_readonly
    from hermes_cli.config_backend import read_config_doc

    # The general loader deliberately recovers from malformed user configuration.
    # An admission policy must not silently disappear in that recovery path.
    try:
        raw = read_config_doc(get_config_path())
    except FileNotFoundError:
        raw = None
    if raw is not None and not isinstance(raw, dict):
        raise ValueError("invalid configuration")
    return load_config_readonly().get("gateway", {}).get("admission_policy")


def _source_fields(source: Any) -> dict[str, str | None]:
    def value(name: str) -> str | None:
        item = source.get(name) if isinstance(source, dict) else getattr(source, name, None)
        return str(getattr(item, "value", item)) if item is not None else None
    return {key: value(key) for key in ("platform", "user_id", "chat_id", "chat_type", "thread_id")}


async def _exchange(command: list[str], frame: bytes, timeout: float) -> bytes:
    proc = await asyncio.create_subprocess_exec(
        *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, limit=MAX_FRAME + 1,
        start_new_session=os.name == "posix",  # detached-spawn: ok — awaited command; finally kills group on timeout/cancellation
    )
    try:
        async with asyncio.timeout(timeout):
            proc.stdin.write(frame)
            await proc.stdin.drain()
            proc.stdin.close()
            # Bound output while reading, rather than after communicate buffers it all.
            chunks = []
            size = 0
            while chunk := await proc.stdout.read(min(8192, MAX_FRAME + 1 - size)):
                size += len(chunk)
                if size > MAX_FRAME:
                    raise ValueError("oversized policy response")
                chunks.append(chunk)
            output = b"".join(chunks)
            await proc.wait()
            if proc.returncode:
                raise ValueError("policy command failed")
            return output
    finally:
        if os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGKILL)  # windows-footgun: ok -- POSIX-only process-group branch
            except ProcessLookupError:
                pass
        elif proc.returncode is None:
            proc.kill()
        await proc.wait()  # health: allow HX006 -- command/group killed above; reap without reading inherited pipes


async def admit_gateway_event(
    kind: str, source: Any, *, text: str = "", message_id: str | None = None,
) -> AdmissionDecision:
    """Allow by default; when configured, only a valid explicit allow proceeds.

    ``deny`` consumes the event. An optional reply is returned only for messages;
    callers keep their existing transport delivery/authentication responsibilities.
    Cancellation kills the command, then propagates without allowing ingress.
    """
    try:
        settings = _settings()
        if settings is None:
            return AdmissionDecision(True)
        if not isinstance(settings, dict) or set(settings) - {"command", "timeout_seconds"}:
            raise ValueError("invalid policy settings")
        command = settings.get("command")
        timeout = settings.get("timeout_seconds", 60)
        if (not isinstance(command, list) or not command
                or any(not isinstance(arg, str) or not arg for arg in command)
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 900):
            raise ValueError("invalid policy command or timeout")
        frame = json.dumps({"version": 1, "kind": kind, "source": _source_fields(source),
                            "text": text, "message_id": message_id}, allow_nan=False).encode()
        if len(frame) > MAX_FRAME:
            raise ValueError("oversized policy request")
        result = json.loads(await _exchange(command, frame, timeout))
        if not isinstance(result, dict) or set(result) - {"decision", "reply"}:
            raise ValueError("invalid policy verdict")
        if result.get("decision") == "allow" and set(result) == {"decision"}:
            return AdmissionDecision(True)
        reply = result.get("reply")
        if result.get("decision") != "deny" or (reply is not None and (
                not isinstance(reply, str) or not reply.strip() or len(reply) > 16000)):
            raise ValueError("invalid policy denial")
        return AdmissionDecision(False, reply if kind == "message" else None)
    except Exception:  # health: allow BLE001 -- every policy/config/protocol failure denies ingress
        logger.warning("Gateway admission policy failed; event denied", exc_info=False)
        return AdmissionDecision(False, PAUSED if kind == "message" else None)


async def check_gateway_message(runner: Any, event: Any) -> AdmissionDecision:
    """Read the routed profile's policy, including secondary-profile conversations."""
    from gateway.run_inbound_consumer import _routed_scope
    async with _routed_scope(runner, event.source):
        return await admit_gateway_event(
            "message", event.source, text=event.text or "", message_id=str(event.message_id or ""))
