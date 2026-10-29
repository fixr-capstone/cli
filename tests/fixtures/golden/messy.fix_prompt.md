# Security fixes for this project

You are helping someone fix security problems that Fixr, an automated scanner, found in their Python code. They may not be a developer and may not be able to review code changes, so work carefully and explain in plain words.

Fixr found 7 issues: 6 to fix, 1 lower-priority one grouped by type, and 0 likely false alarms.

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

## Fix these (6)

### 1. Possible hardcoded password

- Severity: high
- Where: `app.py:7`
- Scanner rule: B105

Flagged code:

```python
API_TOKEN = "sk-live-4f9a2b8c1d3e4f5a6b7c8d9e0f1a2b3c"
```

What is wrong:

The literal string assigned to `API_TOKEN` is a secret that will be checked into source control, making it publicly accessible. An attacker who can read the repository can reuse that token to authenticate to the target service, potentially compromising data or paying for services.  

Fix: Remove the literal from the file, load it from a protected source, and treat the current value as compromised.

(see the suggested fix)

After moving the token, rotate the exposed value immediately.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
import os

# Load token from environment or secret manager
API_TOKEN = os.getenv("API_TOKEN")

if not API_TOKEN:
    raise RuntimeError("API_TOKEN not set in environment")
```

### 2. Use of weak MD5 hash for security. Consider usedforsecurity=False

- Severity: high
- Where: `app.py:10`
- Scanner rule: B324

Flagged code:

```python
    return hashlib.md5(password.encode()).hexdigest()
```

What is wrong:

The code hashes the supplied password with MD5, which is collision‑vulnerable and fast, making brute‑force or rainbow‑table attacks trivial. Since the input comes from an attacker‑controlled source (a user’s password), this is a real security flaw.

Replace MD5 with a password‑hashing KDF such as bcrypt:

(see the suggested fix)

Store the returned hash (bytes or its base64 representation) and verify later with `bcrypt.checkpw`. This ensures the hash is computationally expensive and salted, protecting against offline attacks.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
import bcrypt

def hash_password(password: str) -> bytes:
    # bcrypt automatically generates a random 16‑byte salt and applies 12 rounds
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### 3. Possible SQL injection vector through string-based query construction.

- Severity: high
- Where: `app.py:16`
- Scanner rule: B608

Flagged code:

```python
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    result = db.execute(query)
```

What is wrong:

The query string is built by concatenating the value of `user_id` into the SQL. If an attacker supplies something like `1'; DROP TABLE users;--`, the resulting statement becomes:

SELECT * FROM users WHERE id = '1'; DROP TABLE users;--'

This executes two statements—select and drop—so an attacker can modify or delete data.

Fix

Use a parameterized query, letting the driver escape the value:

(see the suggested fix)

(For drivers that use `%s` placeholders, replace `?` with `%s` and pass `(user_id,)` accordingly.) This ensures the input is treated strictly as data, eliminating injection risk.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    result = db.execute(query, (user_id,))
    return result
```

### 4. Possible SQL injection vector through string-based query construction.

- Severity: high
- Where: `app.py:21`
- Scanner rule: B608

Flagged code:

```python
    db.execute("DELETE FROM users WHERE id = " + user_id)
    return {"status": "deleted"}
```

What is wrong:

The query concatenates `user_id` directly into the SQL string, so an attacker can inject arbitrary SQL if `user_id` comes from user input. The risk is that the database could delete additional rows, alter data, or expose sensitive information.  
Check whether `user_id` is supplied by a trusted source; if not, treat it as untrusted and always use a parameterized statement.  

Fix  
(see the suggested fix)
This sends the query and the parameter separately to the database driver, preventing any injected SQL from being executed.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
def delete_account(user_id):
    # use a placeholder appropriate for the driver (e.g., ? for sqlite3, %s for psycopg2)
    sql = "DELETE FROM users WHERE id = ?"
    db.execute(sql, (user_id,))
    return {"status": "deleted"}
```

### 5. Call to requests without timeout

- Severity: medium
- Where: `app.py:26`
- Scanner rule: B113

Flagged code:

```python
        return requests.get(url, headers={"Authorization": API_TOKEN}).json()
    except:
```

What is wrong:

The request can hang indefinitely if the remote host is slow or unresponsive, tying up your process and potentially causing a denial‑of‑service.  
Add a timeout and catch only the expected exception types.

(see the suggested fix)

If `API_TOKEN` or `url` can be supplied by an attacker, ensure they are validated before use.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
import requests
from requests.exceptions import RequestException

def fetch_external_data(url: str) -> dict | None:
    try:
        # 5‑second timeout is a reasonable default; adjust as needed
        return requests.get(url, headers={"Authorization": API_TOKEN},
                            timeout=5).json()
    except RequestException:
        # Log or handle the specific failure; do not swallow all errors
        return None
```

### 6. Standard pseudo-random generators are not suitable for security/cryptographic purposes.

- Severity: medium
- Where: `app.py:13`
- Scanner rule: B311

Flagged code:

```python
    return 2 ** attempt + random.random()
```

What is wrong:

B311: Standard pseudo-random generators are not suitable for security/cryptographic purposes.

## Lower-priority issues, grouped by type

Each group is one pattern. Fix a group the same way everywhere, or explain why it is safe here.

### B110: Try, Except, Pass detected. (1 place)

- Severity: low
- Where: `app.py:27`

## Optional style clean-up

The linter also left 10 style notes. These are not security problems. Do not fix them by hand; if the person wants them gone, suggest running a formatter such as `ruff format` or `black`, as a separate change.

- E302: expected 2 blank lines, found 1 (6)
- F821: undefined name 'db' (2)
- F401: 'os' imported but unused (1)
- E722: do not use bare 'except' (1)

## When you are done

Give the person a short summary: which issues you fixed, which you left and why, and anything they must do themselves.
