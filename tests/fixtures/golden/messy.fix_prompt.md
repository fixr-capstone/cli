# Security fixes for this project

You are helping someone fix security problems that Fixr, an automated scanner, found in their Python code. They may not be a developer and may not be able to review code changes, so work carefully and explain in plain words.

Fixr found 6 issues: 4 to fix, 1 lower-priority one grouped by type, and 1 likely false alarm.

## How to work

1. Fix the issues under "Fix these" one at a time, in the order listed. The most serious come first.
2. Change only what each fix needs. Do not refactor, rename or reformat unrelated code.
3. Keep the program doing what it does today, apart from closing the security hole.
4. If a fix needs a new setting, secret or package, tell the person exactly what to do, step by step.
5. If an issue looks like a false alarm in this code, say why and leave the code alone.
6. After each fix, explain in one or two plain sentences what changed and why it matters.
7. Do not touch the "Likely false alarms". Handle the lower-priority groups only after the main fixes, and only if the person agrees.
8. If the project has tests, run them after the changes.

> **A secret may be written in the code.** If it is a real key or password, moving it out of the code is not enough: anyone who saw the code may already have it. Tell the person to create a new one with the service that issued it and delete the old one.

## Fix these (4)

### 1. Possible hardcoded password

- Severity: high
- Where: `app.py:6`
- Scanner rule: B105

Flagged code:

```python
API_TOKEN = "sk-live-4f9a2b8c1d3e4f5a6b7c8d9e0f1a2b3c"
```

What is wrong:

The literal token is stored in the source file, so anyone who can read the repository (including anyone who clones the repo or pulls from a CI server) can use it to authenticate to the service. If the token is ever pushed to a public repository or shared inadvertently, the attacker can immediately access the account or data associated with that key, leading to data loss or service abuse.  

Move the value out of the code and retrieve it at runtime. For example, read it from an environment variable and fail early if it’s missing.  

(see the suggested fix)

Suggested fix (a starting point, adapt it to the surrounding code):

```python
# app.py
import os

# The token should be supplied by the deployment environment
API_TOKEN = os.getenv("API_TOKEN")
if not API_TOKEN:
    raise RuntimeError("API_TOKEN environment variable is required")
```

### 2. Possible SQL injection vector through string-based query construction.

- Severity: high
- Where: `app.py:15`
- Scanner rule: B608

Flagged code:

```python
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    result = db.execute(query)
```

What is wrong:

The query builds a literal SQL string by concatenating the `user_id` value, so an attacker could inject arbitrary SQL through a specially crafted `user_id`.  
Fix by using a parameterized query so the driver handles escaping:

(see the suggested fix)

This ensures `user_id` is treated as a data value, not executable code.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    result = db.execute(query, (user_id,))  # or '?' for SQLite
    return result
```

### 3. Possible SQL injection vector through string-based query construction.

- Severity: high
- Where: `app.py:20`
- Scanner rule: B608

Flagged code:

```python
    db.execute("DELETE FROM users WHERE id = " + user_id)
    return {"status": "deleted"}
```

What is wrong:

`user_id` is concatenated straight into the SQL string. If an attacker supplies something like `1; DROP TABLE users; --`, the statement sent to the database becomes two commands, potentially deleting your table. The driver sees the entire string as a single query, so no validation occurs.

Fix: Use a parameterized statement so the driver treats the value as data, not code.

(see the suggested fix)

Replace `?` (or `%s` for some drivers) with the appropriate placeholder for your database library. This prevents injection because the value is bound separately from the query text.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
def delete_account(user_id):
    # Ensure user_id is an integer or cast it if necessary
    db.execute("DELETE FROM users WHERE id = ?", (int(user_id),))
    return {"status": "deleted"}
```

### 4. Call to requests without timeout

- Severity: medium
- Where: `app.py:25`
- Scanner rule: B113

Flagged code:

```python
        return requests.get(url, headers={"Authorization": API_TOKEN}).json()
    except:
```

What is wrong:

The request can block forever if the remote host stalls or the network is slow, exhausting your process’s resources and opening the door to a denial‑of‑service. Add a timeout and handle only relevant exceptions.

(see the suggested fix)
This guarantees the call returns within 5 s and logs any failure instead of silently ignoring it.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
import requests
import logging

def fetch_external_data(url):
    try:
        response = requests.get(url,
                                headers={"Authorization": API_TOKEN},
                                timeout=5)          # seconds
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:      # covers timeouts, DNS, HTTP errors
        logging.error(f"Failed to fetch {url}: {e}")
        return None
```

## Lower-priority issues, grouped by type

Each group is one pattern. Fix a group the same way everywhere, or explain why it is safe here.

### B110: Try, Except, Pass detected. (1 place)

- Severity: low
- Where: `app.py:26`

## Likely false alarms, leave these alone

Fixr's review found these are not real problems in this code. Do not change them.

- `app.py:12` B311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.. The random number is only used to add jitter to an exponential‑backoff delay, not to create a token or secret.

## Optional style clean-up

The linter also left 9 style notes. These are not security problems. Do not fix them by hand; if the person wants them gone, suggest running a formatter such as `ruff format` or `black`, as a separate change.

- E302: expected 2 blank lines, found 1 (5)
- F821: undefined name 'db' (2)
- F401: 'os' imported but unused (1)
- E722: do not use bare 'except' (1)

## When you are done

Give the person a short summary: which issues you fixed, which you left and why, and anything they must do themselves.
