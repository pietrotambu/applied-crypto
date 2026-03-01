SYSTEM_PYTHON ?= python3.12
VENV_DIR ?= .venv
PYTHON ?= $(VENV_DIR)/bin/python
PIP ?= $(PYTHON) -m pip
CLI ?= $(PYTHON) -m padding_oracle.cli

.DEFAULT_GOAL := help

.PHONY: help venv install install-editable run task2 task3 task4 timing-stats test

help:
	@echo "Targets:"
	@echo "  venv              Create local virtual environment in .venv"
	@echo "  install           Install dependencies from requirements.txt"
	@echo "  install-editable  Install package in editable mode (adds padding-oracle command)"
	@echo "  run               Run any CLI command. Example: make run COMMAND='task2'"
	@echo "  task2             Run task2 demo (use ARGS for options)"
	@echo "  task3             Run task3 demo (use ARGS for options)"
	@echo "  task4             Run task4 benchmark (use ARGS for options)"
	@echo "  timing-stats      Analyze long/short journey timing stats (use ARGS for options)"
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
		echo "Usage: make run COMMAND='task2'"; \
		echo "Example: make run COMMAND='task4 --trials 3 --jitters-ms 1,2,3,4'"; \
		exit 1; \
	fi
	$(CLI) $(COMMAND)

task2: $(PYTHON)
	$(CLI) task2 $(ARGS)

task3: $(PYTHON)
	$(CLI) task3 $(ARGS)

task4: $(PYTHON)
	$(CLI) task4 $(ARGS)

timing-stats: $(PYTHON)
	$(PYTHON) -m padding_oracle.timing_stats $(ARGS)

test: $(PYTHON)
	$(PYTHON) -m unittest discover -s tests -v

submit-%: ./batch/%.sub
	@bsub < ./batch/$*.sub
