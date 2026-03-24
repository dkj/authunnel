# AGENTS.md

Instructions for contributors and coding agents working in this repository.

## Project goals

- Keep the codebase **small, clear, and auditable**.
- Prefer straightforward control flow over clever abstractions.
- Make security-sensitive behavior explicit and easy to review.

## Coding guidelines

1. **Minimize complexity**
   - Avoid introducing new dependencies unless clearly justified.
   - Keep functions short and single-purpose.
   - Prefer explicit error handling with contextual messages.

2. **Preserve auditability**
   - Add comments for protocol logic (OAuth2, SOCKS5, websocket bridging), especially where byte-level behavior is implemented.
   - Avoid hidden side effects and global mutable state.
   - Favor deterministic behavior and clear startup/runtime failure modes.

3. **Document behavior**
   - Update `README.md` when CLI flags, runtime flows, or architecture change.
   - Keep examples runnable and aligned with actual code paths.

4. **Testing expectations**
   - Add or update tests for behavior changes.
   - Keep tests readable and focused on externally observable behavior.
   - Run the full suite before finalizing changes:
     - `go test ./...`

## PR quality bar

- Changes should be understandable by a new maintainer in one reading pass.
- If code grows in complexity, explain why in the PR summary.
- Prefer small incremental PRs over broad rewrites.
