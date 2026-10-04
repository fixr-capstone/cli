from fixr_cli.cli import main

# flake8 checks files in worker processes, and macOS starts those by re-importing __main__.
if __name__ == "__main__":
    raise SystemExit(main())
