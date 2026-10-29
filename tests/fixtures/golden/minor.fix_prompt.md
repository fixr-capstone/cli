# Security fixes for this project

You are helping someone fix security problems that Fixr, an automated scanner, found in their Python code. They may not be a developer and may not be able to review code changes, so work carefully and explain in plain words.

Fixr found 1 issue: 1 to fix, 0 lower-priority ones grouped by type, and 0 likely false alarms.

## How to work

1. Fix the issues under "Fix these" one at a time, in the order listed. The most serious come first.
2. Change only what each fix needs. Do not refactor, rename or reformat unrelated code.
3. Keep the program doing what it does today, apart from closing the security hole.
4. If a fix needs a new setting, secret or package, tell the person exactly what to do, step by step.
5. If an issue looks like a false alarm in this code, say why and leave the code alone.
6. After each fix, explain in one or two plain sentences what changed and why it matters.
7. Do not touch the "Likely false alarms". Handle the lower-priority groups only after the main fixes, and only if the person agrees.
8. If the project has tests, run them after the changes.

## Fix these (1)

### 1. Call to requests without timeout

- Severity: medium
- Where: `profile.py:4`
- Scanner rule: B113

Flagged code:

```python
    resp = requests.get("https://api.internal/users/" + str(user_id))
    resp.raise_for_status()
```

What is wrong:

The call to `requests.get` can hang indefinitely if the remote server delays or stalls, causing your application to block or run out of resources.  
Add a timeout to limit how long the request waits, e.g.:

(see the suggested fix)

Adjust the timeout value to suit your tolerance for latency, and ensure the user‑controlled `user_id` is validated or sanitized as needed.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
def fetch_profile(user_id):
    resp = requests.get(
        "https://api.internal/users/" + str(user_id),
        timeout=5.0          # seconds
    )
    resp.raise_for_status()
    return resp.json()
```

## Optional style clean-up

The linter also left 1 style note. These are not security problems. Do not fix them by hand; if the person wants them gone, suggest running a formatter such as `ruff format` or `black`, as a separate change.

- E302: expected 2 blank lines, found 1 (1)

## When you are done

Give the person a short summary: which issues you fixed, which you left and why, and anything they must do themselves.
