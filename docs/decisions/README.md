# Decisions

One short file per decision that would be expensive to change later: the data model, how
sign-in works, which grants the app needs, what is stored where and for how long, an
external service it depends on. Small choices that the code and its tests already explain
don't need one.

- Name: `NNNN-short-title.md`, numbered in order (`0002-...`, `0003-...`). Never renumber.
- Copy [`0000-template.md`](0000-template.md). Keep it to one screen.
- A decision is never edited to say something else: write a new one that supersedes it and
  set the old one's status to `Superseded by NNNN`.
- Write it in the same commit as the change it explains, or before it.

Small apps may never have more than [0001](0001-record-decisions.md). That is fine.
