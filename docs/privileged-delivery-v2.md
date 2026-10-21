# Privileged delivery v2 contract

The v1 field numbers and enum values remain unchanged. New consumers must
negotiate protocol 2 with a stable service ID before the panel can approve a
v2 task. Negotiation advertises installed support; it is never approval.
Legacy monitoring remains supported. Legacy terminal privileged reports and
CompleteManualUpgrade cannot complete a v2 task.

## Independent facts

- Desired revision changes configuration content; update_sequence changes on
  receipt, approval, operation progress and daemon observation as well.
- Receipt never changes approval. Confirmation requires fresh panel 2FA.
- A host operation records local administration. LOCAL_APPLIED does not update
  the daemon applied pointer. Only a matching daemon observation can do that.
- Current applied is a durable pointer, independent of paginated history.
- A new desired revision supersedes pending old approvals. Retry IDs cannot be
  reused with changed content. Approval expiry does not erase history.

## Hash: privileged-settings-v1

Normalize absent optional booleans to false. Hash these bytes with SHA-256 and
encode as lowercase hexadecimal:

1. UTF-8 `komari.privileged-settings.v1` followed by a zero byte.
2. Five bytes, each 0 or 1, in order: remote_control_enabled, webssh_enabled,
   execution_enabled, enable_gpu, rescue_helper_enabled.
3. required_privilege_mode as four unsigned big-endian bytes, including zero
   when unspecified. Reject invalid enum values before hashing.

The same testdata/privileged-settings-v1.json vectors apply to Go and TS. Hashing
is explicitly independent of JSON ordering and protobuf optional-field presence.

## Signatures

A v2 revision uses SignedInstruction.instruction_type
`komari.config.v2.PrivilegedRevision`. Its body is deterministic protobuf of the
**entire** PrivilegedRevision with signature unset. It covers state, approval
metadata, hash, service/action binding, generation and deadline, including the
embedded HostAuthorization. A host execution lease uses instruction_type
`komari.host.v1.HostOperation`, and signs the entire HostOperation with signature
unset. A signature for a revision cannot authorize a host operation.

No maps are used in approval bodies. Reject unknown authorization fields when
validating rather than dropping fields before signature comparison. Signed
bytes must equal the canonical body the receiver expects. A config hash by
itself is not approval. Nonce possession and local_authentication text are not
proof of OS authentication; the administrator-owned local tool enforces that.

Prepare claims the approved nonce once, binding it to an operation ID and a lease
no longer than ten minutes or the original approval deadline. Retrying the same
operation does not extend it. Get can recover an expired operation as history;
a new signature on recovered history does not renew the lease. A failed/restored
operation may be reported after expiry. Successful host work must be reported
within the lease. A persisted successful host operation allows its daemon ACK
to be retried after expiry, provided the target is still current.

Passwords never appear in any RPC or task. No task contains arbitrary shell,
a user-specified executable, or an arbitrary download URL.

## Bootstrap and supported fields

Initial baseline creation/ACK is implemented in the later enrollment stage;
protocol negotiation alone must not fabricate r1/applied=1. Clients advertise
supported runtime field numbers and host tool version. Unsupported runtime
fields are rejected explicitly, never ignored while advancing applied.
