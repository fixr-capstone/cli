# fixr CLI

`fixr` runs the Fixr pipeline on your own machine: the four scanners from
[static-analysis-bundle](https://github.com/fixr-capstone/static-analysis-bundle), the
false-alarm classifier and ranking from [ML-filtering-](https://github.com/fixr-capstone/ML-filtering-),
and the explanations and chat from [RAG-implementation](https://github.com/fixr-capstone/RAG-implementation).
It reports the same findings as the website, and it also audits dependencies listed only in
`requirements.txt`.

Your code stays on your machine. The one exception: if you set `GROQ_API_KEY`, the functions
around the top 5 Bandit findings are sent to Groq to be explained.

## Install

You need [uv](https://docs.astral.sh/uv/). uv downloads Python 3.13 itself if you don't have it.

```bash
git clone https://github.com/fixr-capstone/cli.git
cd cli
uv tool install --overrides overrides.txt .
```

`--overrides overrides.txt` is required. Without it, uv follows a setting in fixr-rag that fetches
ml-filtering over SSH, and the install fails unless you have a GitHub SSH key.

To work on the CLI itself, run `uv sync` in the clone and prefix commands with `uv run`.

## Scan

```bash
fixr scan                       # the current folder
fixr scan path/to/project       # a folder, a single .py file, or a .zip
fixr scan . --fix-prompt fix.md # also write a prompt for an AI coding tool
fixr scan . --format json > results.json
```

| Option | Effect |
|---|---|
| `--format text\|json` | Terminal report (default) or JSON on stdout |
| `--fix-prompt FILE` | Write the website's "fix with AI" prompt to FILE |
| `--no-explain`, `--explain N` | Skip Groq explanations, or explain the top N Bandit findings (default 5) |
| `--show-style` | List every flake8 style note instead of a one-line summary |
| `--fail-on none\|low\|medium\|high` | Severity that makes the exit code 1 (default `high`) |
| `--verbose` | Show the scanners' own log output |

Exit codes: `0` means nothing at or above `--fail-on`, `1` means there is something, and `2`
means a usage error or a scan that could not run. Style notes and likely false alarms never
count towards the exit code.

## Groq key

Explanations and `fixr chat` need a [Groq](https://console.groq.com/keys) API key. Without one,
`fixr scan` still works and tells you so.

For this terminal only:

```bash
export GROQ_API_KEY="gsk_..."      # macOS and Linux
```

```powershell
$env:GROQ_API_KEY="gsk_..."        # Windows PowerShell
```

To keep it for every terminal, add the `export` line above to `~/.zshrc` (macOS) or `~/.bashrc`
(Linux) and open a new terminal. On Windows, run this once and open a new terminal:

```powershell
setx GROQ_API_KEY "gsk_..."
```

Or put it in a `.env` file. fixr-rag loads one with python-dotenv, which looks upward from where
the package is installed, not from the folder you run `fixr` in. For a `uv tool install` that
means a `~/.env` file containing `GROQ_API_KEY=gsk_...`; in a development checkout run with
`uv run fixr` it means `cli/.env` (gitignored).

## Explanations and chat

The classifier drops a Bandit finding only when it is under 10% likely to be real, and never
drops a high-severity one. A high-severity finding below that line is kept and starts with
"Likely false alarm: Fixr's classifier puts the chance this is real at N%". When an explanation
says a finding is harmless, or the classifier doubts a kept one, `fixr` lists it under "Likely
false alarms" instead of counting it, and marks it `"likely_false_alarm": true` in JSON.

`fixr chat` lets you ask questions about a scan. It needs a key.

```bash
fixr chat path/to/project           # scan, then chat
fixr chat --from results.json       # chat about a saved JSON scan
```

Inside the chat, `/list` shows the findings, `/focus N` points the questions at finding N, and
`/quit` leaves.

## How it differs from the website

- **pip-audit always runs when there is a dependency file.** The backend skips it when a project
  has no `pyproject.toml`. `fixr` resolves the full dependency tree, so vulnerable transitive
  packages are reported too. If resolution fails and every requirement is pinned with `==`, it
  falls back to checking the pinned versions and says so in the scanner list.
- **Dependency findings are readable.** A pip-audit hit is shown as "cryptography 45.0.6 has a
  known vulnerability" with a short advisory summary. Each package gets one line with the lowest
  version that fixes all of its advisories.
- **The false-alarm check is wider.** It also catches phrasings such as "No change to the enum is
  required". It only applies to findings that have an explanation, so an advisory's own wording
  never hides it.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check src tests
```

`src/fixr_cli/findings.py` and `fix_prompt.py` are ports of the website's `lib/api.ts` and
`lib/fixPrompt.ts`. Their tests compare against outputs generated from the TypeScript itself. With
the frontend repo checked out next to this one, regenerate them with:

```bash
node --experimental-strip-types --no-warnings tests/fixtures/make_goldens.mts
```
