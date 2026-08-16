.PHONY: install dev test lint demo render clean

install:
	python3 -m pip install -e .

dev:
	python3 -m pip install -e ".[dev]"

test:
	python3 -m pytest

lint:
	python3 -m ruff check src tests

demo:
	sentinelgate --config config.example.toml demo

render:
	sentinelgate --config config.example.toml render

clean:
	python3 -c 'from pathlib import Path; [p.unlink() for p in Path(".").rglob("*.pyc")]; [p.rmdir() for p in sorted(Path(".").rglob("__pycache__"), reverse=True) if not any(p.iterdir())]'

