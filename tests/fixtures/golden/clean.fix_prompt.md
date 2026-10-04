# Security fixes for this project

You are helping someone fix security problems that Fixr, an automated scanner, found in their Python code. They may not be a developer and may not be able to review code changes, so work carefully and explain in plain words.

Fixr found 0 issues: 0 to fix, 0 lower-priority ones grouped by type, and 0 likely false alarms.

## How to work

1. Fix the issues under "Fix these" one at a time, in the order listed. The most serious come first.
2. Change only what each fix needs. Do not refactor, rename or reformat unrelated code.
3. Keep the program doing what it does today, apart from closing the security hole.
4. If a fix needs a new setting, secret or package, tell the person exactly what to do, step by step.
5. If an issue looks like a false alarm in this code, say why and leave the code alone.
6. After each fix, explain in one or two plain sentences what changed and why it matters.
7. Do not touch the "Likely false alarms". Handle the lower-priority groups only after the main fixes, and only if the person agrees.
8. If the project has tests, run them after the changes.

## Optional style clean-up

The linter also left 2 style notes. These are not security problems. Do not fix them by hand; if the person wants them gone, suggest running a formatter such as `ruff format` or `black`, as a separate change.

- F401: 'sqlite3' imported but unused (1)
- E302: expected 2 blank lines, found 1 (1)

## When you are done

Give the person a short summary: which issues you fixed, which you left and why, and anything they must do themselves.
