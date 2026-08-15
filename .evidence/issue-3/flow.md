# Issue #3 verification

The broker/API portion was exercised against a real local `capdel.py serve` process by
`test/approval_routing.py` (not a mock):

- an escalation invoked the configured hook exactly once;
- the hook envelope led with `granted_if_approved` and carried `reason` unchanged;
- owner-only `GET /_requests` and `POST /_requests/<id>/approve` were checked;
- approval returned `{ok, cap_id}` with no token, and the requester's authenticated poll
  returned the token;
- widening the stored `want` was clamped to the immutable filed shape.

The owner approval dashboard is implemented in `pod/relay.ts`, but this repository has no
capdel deployed staging target on this box. A signed-in deployed-staging browser walk and
step screenshots remain operator-run evidence; no screenshot is presented as staging proof.
