# MuhGPT developer tasks. First run:  make install  (needs Python >= 3.9)
.PHONY: help install lint test guard-selftest check

PY   ?= python3
CODE := main.py muhgpt tests scripts

help:
	@echo "make install         install the package with dev extras (pytest, ruff)"
	@echo "make check           lint + guard self-test + full suite (the release gate)"
	@echo "make lint            ruff over the project code"
	@echo "make test            run the pytest suite"
	@echo "make guard-selftest  assert the guard classifies key commands correctly"

install:
	$(PY) -m pip install -e ".[dev]"

lint:
	$(PY) -m ruff check $(CODE)

test:
	$(PY) -m pytest -q

guard-selftest:
	$(PY) scripts/guard_selftest.py

# The gate to run before packaging / shipping a release.
check: lint guard-selftest test
