# Security fixes for this project

You are helping someone fix security problems that Fixr, an automated scanner, found in their Python code. They may not be a developer and may not be able to review code changes, so work carefully and explain in plain words.

Fixr found 82 issues: 4 to fix, 77 lower-priority ones grouped by type, and 1 likely false alarm.

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
- Where: `custom-file-operation-protocol-main/models/response_codes.py:19`
- Scanner rule: B105

Flagged code:

```python
    SUCCESSFUL_PASSWORD_CHANGE = "1:pw"
    SUCCESSFUL_SESSION_REFRESH = "1:ref"
```

What is wrong:

The value `"1:pw"` is only an enum member used to tag a successful password‑change event; it is not an actual password or secret. Bandit’s rule triggers because it detects a string that could be a password, but the context shows it’s just a status code.  
Fix: No change to the enum is required. If you want to silence the warning, you can add a comment telling Bandit to ignore this line:

(see the suggested fix)

Alternatively, rename the flag to make its purpose clearer, e.g., `PW_CHANGE_SUCCESS = "1:pw"`. No secret handling or environment variable is needed here.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
class SuccessFlags(Enum):
    ...
    # Password change success indicator – not a secret.
    SUCCESSFUL_PASSWORD_CHANGE = "1:pw"  # pragma: no cover
    ...
```

### 2. Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

- Severity: low
- Where: `custom-file-operation-protocol-main/client/cmd/client_window.py:187`
- Scanner rule: B101

Flagged code:

```python
        assert self.session_master.identity
        parsed_args: argparse.Namespace = command_parsers.filedir_parser.parse_args(shlex.split(args))
```

What is wrong:

`assert self.session_master.identity` is only guaranteed to run when Python isn’t started with the `-O` flag. If the binary is built in optimized mode, the assertion disappears and `self.session_master.identity` may become `None`.  
The rest of the routine passes this value as `subject_file_owner`, so an omitted or null identity would propagate into file creation logic and could grant the wrong ownership or lead to downstream errors.

Replace the assert with a runtime guard that raises a real exception:

(see the suggested fix)

Now the check is enforced regardless of optimization level.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
async def do_create(self, args: str) -> None:
    """
    CREATE [filename] [MODIFIERS]
    Create a new file in the remote directory.
    Filename must include file extension
    """
    if not self.session_master.identity:
        raise RuntimeError("Session identity is required for file creation")

    parsed_args: argparse.Namespace = command_parsers.filedir_parser.parse_args(shlex.split(args))
    file_component: BaseFileComponent = BaseFileComponent(
        subject_file=parsed_args.file,
        subject_file_owner=self.session_master.identity,
    )
    self.end_connection = parsed_args.bye
# ...
```

### 3. Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

- Severity: low
- Where: `custom-file-operation-protocol-main/client/cmd/client_window.py:204`
- Scanner rule: B101

Flagged code:

```python
        assert self.session_master.identity
        parsed_args: argparse.Namespace = command_parsers.filedir_parser.parse_args(shlex.split(args))
```

What is wrong:

`assert self.session_master.identity` only checks that an identity is present while running in a non‑optimized interpreter. In an optimized run (`python -O`), this assertion is stripped, so the method could call `delete_file` with `subject_file_owner=None`. If the identity is missing, the deletion proceeds as if an authenticated user performed it, enabling unauthorized file removal.  

Fix

Replace the assertion with an explicit check that raises a clear exception when the identity is absent.

(see the suggested fix)

Now the method fails explicitly when the identity is missing, regardless of optimization flags.

Suggested fix (a starting point, adapt it to the surrounding code):

```python
async def do_delete(self, args: str) -> None:
    '''
    DELETE [filename] [modifiers]
    Delete a file from a remote directory.
    Filename must include file extension
    '''
    if not self.session_master.identity:
        raise ValueError("Session identity missing: cannot delete files.")
    parsed_args: argparse.Namespace = command_parsers.filedir_parser.parse_args(shlex.split(args))
    file_component: BaseFileComponent = BaseFileComponent(
        subject_file=parsed_args.file,
        subject_file_owner=self.session_master.identity
    )
    self.end_connection = parsed_args.bye

# ...
```

### 4. Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

- Severity: low
- Where: `custom-file-operation-protocol-main/client/cmd/client_window.py:402`
- Scanner rule: B101

Flagged code:

```python
        assert self.session_master.identity
        parsed_args: argparse.Namespace = command_parsers.permission_command_parser.parse_args(shlex.split(args))
```

What is wrong:

The assertion guarantees that `self.session_master.identity` is truthy. However, Python removes `assert` statements when the interpreter is run with optimisations (`-O`). If the identity is missing and the code runs optimised, the check disappears, and `transfer_ownership` will execute with a `None` or empty identity, potentially transferring files to the wrong user or leaking permissions. Replace the `assert` with an explicit runtime guard that raises an error regardless of optimisation flags.

(see the suggested fix)

Suggested fix (a starting point, adapt it to the surrounding code):

```python
async def do_transfer(self, args: str) -> None:
    '''
    TRANSFER [filename] [directory] [user] [modifiers]
    Transfer ownership of a file to another user.
    '''
    if not self.session_master.identity:
        raise RuntimeError('Session identity is required for file transfer')
    parsed_args: argparse.Namespace = command_parsers.permission_command_parser.parse_args(shlex.split(args))
    if not parsed_args.user:
        raise ValueError('User needs to be specified')
    permission_component: BasePermissionComponent = BasePermissionComponent(
        subject_file=parsed_args.file,
        subject_file_owner=self.session_master.identity,
        subject_user=parsed_args.user)
    self.end_connection = parsed_args.bye
# ...
```

## Lower-priority issues, grouped by type

Each group is one pattern. Fix a group the same way everywhere, or explain why it is safe here.

### B101: Use of assert detected. The enclosed code will be removed when compiling to optimised byte code. (52 places)

- Severity: low
- Where: `custom-file-operation-protocol-main/client/cmd/client_window.py:422`, `custom-file-operation-protocol-main/client/cmd/client_window.py:436`, `custom-file-operation-protocol-main/client/communication/incoming.py:8`, `custom-file-operation-protocol-main/client/communication/outgoing.py:11`, `custom-file-operation-protocol-main/client/config/constants.py:10`, `custom-file-operation-protocol-main/client/operations/auth_operations.py:99`, `custom-file-operation-protocol-main/client/operations/auth_operations.py:110`, `custom-file-operation-protocol-main/client/operations/auth_operations.py:171`, `custom-file-operation-protocol-main/client/operations/file_operations.py:26`, `custom-file-operation-protocol-main/client/operations/file_operations.py:75`, `custom-file-operation-protocol-main/client/operations/file_operations.py:96`, `custom-file-operation-protocol-main/client/operations/file_operations.py:115` and 40 more

### DEP002: '…' defined as a dependency but not used in the codebase (23 places)

- Severity: low
- Names: `aiohappyeyeballs`, `aiosignal`, `annotated-types`, `anyio`, `async-timeout`, `attrs`, `cffi`, `exceptiongroup`, `frozenlist`, `h11`, `idna`, `multidict`, `propcache`, `psycopg-binary`, `psycopg-pool`, `pycparser`, `pydantic_core`, `referencing`, `rpds-py`, `sniffio` and 3 more
- Where: `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt`, `custom-file-operation-protocol-main/requirements.txt` and 11 more

### B110: Try, Except, Pass detected. (2 places)

- Severity: low
- Where: `custom-file-operation-protocol-main/server/__main__.py:26`, `custom-file-operation-protocol-main/server/logging.py:126`

## Likely false alarms, leave these alone

Fixr's review found these are not real problems in this code. Do not change them.

- `custom-file-operation-protocol-main/models/response_codes.py:50` B105 Possible hardcoded password. The string `'2:exp'` is just a short code used to identify a client‑side error (“expired auth token”).

## Optional style clean-up

The linter also left 200 style notes. These are not security problems. Do not fix them by hand; if the person wants them gone, suggest running a formatter such as `ruff format` or `black`, as a separate change.

- E501: line too long (200)

## When you are done

Give the person a short summary: which issues you fixed, which you left and why, and anything they must do themselves.
