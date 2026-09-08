#!/usr/bin/env python3
"""
Convenience launcher.

  python run.py cli   [--json] ...    -> run a one-off real scan in the terminal
  python run.py api   [--port 8000]   -> start the FastAPI web server + dashboard

Windows 10/11 only: both modes call `netsh wlan`, which is a built-in
Windows component.
"""
import sys
import argparse


def main():
    parser = argparse.ArgumentParser(description="WISRA launcher")
    parser.add_argument("mode", choices=["cli", "api"], help="Run mode")
    parser.add_argument("--port", type=int, default=8000, help="Port for the API server")
    parser.add_argument("--host", default="127.0.0.1", help="Host for the API server")
    args, remaining = parser.parse_known_args()

    if args.mode == "cli":
        sys.argv = [sys.argv[0]] + remaining
        from app.main import main as cli_main
        cli_main()
    else:
        import uvicorn
        uvicorn.run("app.api.routes:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
