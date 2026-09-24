"""Run a relay: ``python -m noknowledge.server --host 0.0.0.0 --port 8000``."""

from __future__ import annotations

import argparse

import uvicorn

from noknowledge.server.app import create_app
from noknowledge.server.config import Settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noknowledge.server",
        description="Run a noknowledge relay (an untrusted, opaque blob store).",
    )
    parser.add_argument("--host", default=None, help="bind address")
    parser.add_argument("--port", type=int, default=None, help="bind port")
    parser.add_argument("--data-dir", default=None, help="relay data directory")
    parser.add_argument(
        "--require-hashcash",
        action="store_true",
        help="require proof-of-work for mailbox and prekey creation",
    )
    parser.add_argument("--log-level", default="info")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    overrides: dict = {}
    if args.host:
        overrides["host"] = args.host
    if args.port:
        overrides["port"] = args.port
    if args.data_dir:
        overrides["data_dir"] = args.data_dir
    if args.require_hashcash:
        overrides["require_hashcash"] = True

    settings = Settings.from_env(**overrides)
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level=args.log_level,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())