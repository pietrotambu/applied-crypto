SYSTEM_PYTHON ?= python3.12
VENV_DIR ?= .venv
PYTHON ?= $(VENV_DIR)/bin/python
PIP ?= $(PYTHON) -m pip
CLI ?= $(PYTHON) -m padding_oracle.cli

.DEFAULT_GOAL := help

.PHONY: help venv install install-editable run boolean timing task4 task4-netem timing-stats test

help:
	@echo "Targets:"
	@echo "  venv              Create local virtual environment in .venv"
	@echo "  install           Install dependencies from requirements.txt"
	@echo "  install-editable  Install package in editable mode (adds padding-oracle command)"
	@echo "  run               Run any CLI command. Example: make run COMMAND='boolean'"
	@echo "  boolean           Run boolean-oracle demo (use ARGS for options)"
	@echo "  timing            Run timing-oracle demo (use ARGS for options)"
	@echo "  task4             Run task4 baseline script (TRIALS/MESSAGE_KB env vars)"
	@echo "  task4-netem       Run task4 loopback netem sweep script"
	@echo "  timing-stats      Analyze timing path separation stats (use ARGS for options)"
	@echo "  test              Run unit tests"

$(PYTHON):
	@$(SYSTEM_PYTHON) -m venv $(VENV_DIR)
	@$(PIP) install -q --upgrade pip

venv: $(PYTHON)

install: $(PYTHON)
	@$(PIP) install -q -r requirements.txt

install-editable: $(PYTHON)
	@$(PIP) install -q -e .

run: $(PYTHON)
	@if [ -z "$(COMMAND)" ]; then \
		echo "Usage: make run COMMAND='boolean'"; \
		echo "Example: make run COMMAND='timing --message-kb 1'"; \
		exit 1; \
	fi
	$(CLI) $(COMMAND)


boolean: $(PYTHON)
	$(CLI) boolean $(ARGS)

timing: $(PYTHON)
	$(CLI) timing $(ARGS)

task4: $(PYTHON)
	TRIALS=$${TRIALS:-3} MESSAGE_KB=$${MESSAGE_KB:-1} ./scripts/task4_baseline.sh

task4-netem: $(PYTHON)
	TRIALS=$${TRIALS:-3} MESSAGE_KB=$${MESSAGE_KB:-1} ./scripts/task4_netem_lo_sweep.sh

timing-stats: $(PYTHON)
	$(PYTHON) -m padding_oracle.timing_stats $(ARGS)

test: $(PYTHON)
	$(PYTHON) -m unittest discover -s tests -v

submit-%: ./batch/%.sub
	@bsub < ./batch/$*.sub
