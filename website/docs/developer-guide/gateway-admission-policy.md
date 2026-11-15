# Required gateway admission command

`gateway.admission_policy` is an optional, required-decision ingress gate for
operator-managed routing. With the default `null`, existing behavior is unchanged.
With a configured command, only an explicit valid `allow` continues to the ordinary
agent. Missing executable, configuration/protocol errors, nonzero exit, oversized
output and timeout deny. This is independent of optional plugin hook failures.

A concrete consumer is the standalone
[scoped collaborator Drive plugin](https://github.com/OmiroAI/hermes-plugins/tree/feature/scoped-collaborator-drive/plugins/scoped-collaborator-drive).
All Google ACL logic, registry/approval policy, worker model choices and SOUL
instructions live there, outside core. It can be deployed at pinned fork commits
before any upstream release. This interface is opt-in hardening; it does not
change Hermes's single-tenant trust or OS isolation boundaries in SECURITY.md.

```yaml
gateway:
  admission_policy:
    command: [/absolute/path/to/policy-command, --operator-config, /etc/policy.json]
    timeout_seconds: 60
```

The argv list is trusted operator configuration, never message/model input. It
runs without a shell and inherits the gateway's OS environment/identity. Protect
the configuration and executable from agent/collaborator writes. Each event
invokes a fresh command; the default timeout is 60 seconds, maximum 900. `null`
disables the feature; `{}`, invalid settings and nonpositive/nonfinite timeouts
deny. Each profile resolves its own settings in the routed runtime scope for
messages. Changing/removing the configured gate is an operator action, not an
integrity boundary against the process owner. No secret belongs in argv.

The command receives one UTF-8 JSON document on stdin, followed by EOF:

```json
{"version":1,"kind":"message","source":{"platform":"telegram","user_id":"SYNTHETIC_USER","chat_id":"SYNTHETIC_CHAT","chat_type":"dm","thread_id":null},"text":"untrusted request","message_id":"SYNTHETIC_MESSAGE"}
```

Source fields come from normalized transport metadata; text is untrusted. Stable
message actors override sender-less shared-session sources; an explicitly empty
actor remains empty. When the transport provides quoted text for the current
message, the frame also includes optional `reply_to_text`. This is untrusted task
context, never authorization or a lookup of previous private conversations. It
shares the frame size limit. Consumers must accept this optional field; deploy
updated consumers with this bridge (older strict consumers safely deny replies).
IDs, platform and chat context must be checked together. An absent identity is
not founder/owner authorization. The payload intentionally excludes histories,
private memory, credentials, arbitrary SDK objects and mutable runner handles.
The same API sends `callback`, `reaction` and `platform_event`; these controls have
no request text or message ID. Missing context must deny, not guess a privilege.

Stdout must be exactly one JSON verdict (no logging):

```json
{"decision":"allow"}
```

or

```json
{"decision":"deny","reply":"Optional bounded response for a consumed message."}
```

Deny never falls through. A command may perform its bounded alternative workflow
and deny with a result. Replies are accepted only for `message`, limited to
16,000 characters; command stdout and input are bounded to 256 KiB. A policy is
responsible for the confidentiality of its reply in the destination chat. Core
does not turn a policy reply into an agent prompt. Controls ignore replies.
On command error the reply is a neutral pause/check-request-status notice; core
cannot infer a mutation from a missing command response. Keep raw
exception text, credentials and private data off stdout and gateway logs.

The gate runs before normal message hooks, commands, history and agent dispatch;
busy steering and producer/relay ingress also check it before privileged handling.
Reaction/platform hooks and Telegram inline callbacks check it before dispatch.
Internal gateway-generated events keep their existing trusted path. Producer
retries or cold/busy transitions may invoke a command again: side effects require
durable idempotency/reconciliation in the consumer. Local CLI, operator APIs,
background automation and other adapters' independent control endpoints are not
turned into collaborator APIs by this feature. Audit any additional exposed
adapter controls before allowing external users.

On cancellation/error/timeout the direct child is killed and reaped. POSIX also
kills its process group; Windows only guarantees termination of the direct child.
A command can escape that group, and a remote API may already have committed a
write. This is not a sandbox, transactional rollback or exactly-once delivery.
Use a separate OS/container identity and a capability broker where hostile-user
containment is needed. A same-process plugin, SOUL rule or broad API credential
cannot provide that isolation.

Tests: `scripts/run_tests.sh tests/gateway/test_admission_policy.py`. The consumer
has its own offline ACL/registry/worker and cross-repository integration tests;
operators must also test installed image/transport/live permissions before exposure.
