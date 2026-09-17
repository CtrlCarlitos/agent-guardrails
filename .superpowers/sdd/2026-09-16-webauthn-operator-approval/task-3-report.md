# Task 3 Report: WebAuthn-Only Browser Completion

## Scope

Implemented Task 3 in the capability-boundary worktree. The loopback browser
page now has WebAuthn assertion completion as its only mutation path.

## Implementation

- `StartBrowser` accepts an assertion-store boundary and serves the exact
  `http://localhost:<port>` RP origin without a URL token or query string.
- The page escapes and presents canonical request fields, calls
  `navigator.credentials.get`, base64url-encodes the credential response, and
  posts it only to `POST /assertion`.
- The assertion endpoint rejects malformed or missing JSON with `404`, failed
  verification with `403`, and expired or consumed requests with `410`.
  It calls `Broker.Approve` only after a verified assertion.
- Form choices, generic browser completion routes, and daemon socket approve
  and deny operations cannot mutate a request. Raw form and JSON attempts keep
  the request pending.
- Added an adapter on `operatorauth.Store` to expose its existing strict
  `BeginAssertion` and `FinishAssertion` ceremonies without an import cycle.

## Tests

- Added a failing-then-passing form-choice regression test.
- Added a failing-then-passing missing-assertion regression test.
- Added loopback page presentation coverage and an `agent-browser` E2E failure
  path. The browser test confirms canonical fields are rendered and that a
  browser without a WebAuthn credential leaves the request pending.

## Verification

Ran successfully:

```text
/usr/local/go/bin/go test ./internal/approval -count=1
/usr/local/go/bin/go test ./internal/operatorauth -count=1
/usr/local/go/bin/go test ./... -count=1
```

## Concern And Follow-up

Task 4 must inject the default `operatorauth.Store` into the daemon. Until it
does, submission stays pending and intentionally opens no browser page rather
than falling back to an unsafe completion route. Successful physical
authenticator approval remains a manual smoke test.

## Fix Round 1

- The page now shows a privacy-safe 12-character request-ID prefix with the
  canonical action fields.
- Browser state owns the current assertion ceremony. Malformed input and
  failed verification leave the broker request pending and immediately replace
  it with a fresh ceremony bound to the same request and absolute expiry.
- Terminal handler paths perform asynchronous graceful server shutdown. A
  completed assertion receives its `200` response, while the loopback listener
  is no longer reachable afterward.
- Added a real Ed25519/COSE credential harness that validates a signed
  assertion through `operatorauth.Store`, completes exactly one broker action,
  and observes `410 Gone` on direct-handler replay.
- The `agent-browser` test explicitly stubs `navigator.credentials.get` to
  reject, invokes the page's assertion function, waits for the rendered
  rejection status, and confirms the request is still pending.
