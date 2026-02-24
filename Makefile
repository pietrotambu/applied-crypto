PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
CLI ?= $(PYTHON) -m padding_oracle.cli

.DEFAULT_GOAL := help

.PHONY: help install install-editable run task2 task3 task4 test

help:
	@echo "Targets:"
	@echo "  install           Install dependencies from requirements.txt"
	@echo "  install-editable  Install package in editable mode (adds padding-oracle command)"
	@echo "  run               Run any CLI command. Example: make run COMMAND='task2'"
	@echo "  task2             Run task2 demo (use ARGS for options)"
	@echo "  task3             Run task3 demo (use ARGS for options)"
	@echo "  task4             Run task4 benchmark (use ARGS for options)"
	@echo "  test              Run unit tests"

install:
	$(PIP) install -r requirements.txt

install-editable:
	$(PIP) install -e .

run:
	@if [ -z "$(COMMAND)" ]; then \
		echo "Usage: make run COMMAND='task2'"; \
		echo "Example: make run COMMAND='task4 --trials 3 --jitters-ms 1,2,3,4'"; \
		exit 1; \
	fi
	$(CLI) $(COMMAND)

task2:
	$(CLI) task2 $(ARGS)

task3:
	$(CLI) task3 $(ARGS)

task4:
	$(CLI) task4 $(ARGS)

test:
	$(PYTHON) -m unittest discover -s tests -v
