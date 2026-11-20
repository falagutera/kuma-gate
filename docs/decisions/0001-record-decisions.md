# 0001. Record expensive decisions here

- Status: Accepted
- Date: 2026-11-08

## Context

The code and its tests say what the app does, AGENTS.md says which rules a change must keep,
and CHANGELOG.md says what changed for the people who use it. None of them says why a costly
choice (data model, sign-in, grants, storage) was made, and that reason is what gets lost first.

## Decision

Decisions that would be expensive to change get a short file in `docs/decisions/`, written
with the change. Everything else stays in the code, the tests and the commit messages.

## Consequences

Someone changing the app later (a person or a coding agent) can see why things are the way
they are before undoing them. The cost is one short file now and then; small apps may never
need more than this one.
