"""Entry point: ``python -m noknowledge.gui``."""

from __future__ import annotations

from noknowledge.gui.app import run


def main(argv: list[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    raise SystemExit(main())