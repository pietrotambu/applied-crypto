SYSTEM_PYTHON ?= python3.12
VENV_DIR ?= .venv
PYTHON ?= $(VENV_DIR)/bin/python
PIP ?= $(PYTHON) -m pip
CLI ?= $(PYTHON) -m padding_oracle.cli

.DEFAULT_GOAL := help

.PHONY: help venv install install-editable run boolean timing victim attacker noise-experiment task4 task4-netem timing-stats test

help:
	@echo "Targets:"
	@echo "  venv              Create local virtual environment in .venv"
	@echo "  install           Install dependencies from requirements.txt"
	@echo "  install-editable  Install package in editable mode (adds padding-oracle command)"
	@echo "  boolean           Run boolean-oracle demo (use ARGS for options)"
	@echo "  timing            Run self-contained local timing attack demo (use ARGS for options)"
	@echo "  victim            Run victim/oracle server (use ARGS for options)"
	@echo "  attacker          Run timing attacker against --addr host:port (use ARGS for options)"
	@echo "  noise-experiment  Run timing robustness experiment under injected jitter (use ARGS for options)"
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

boolean: $(PYTHON)
	$(CLI) boolean $(ARGS)

timing: $(PYTHON)
	$(CLI) timing $(ARGS)

victim: $(PYTHON)
	$(CLI) victim $(ARGS)

attacker: $(PYTHON)
	$(CLI) attacker $(ARGS)

noise-experiment: $(PYTHON)
	$(PYTHON) -m padding_oracle.noise_experiment $(ARGS)

timing-stats: $(PYTHON)
	$(PYTHON) -m padding_oracle.timing_stats $(ARGS)

test: $(PYTHON)
	$(PYTHON) -m unittest discover -s tests -v

submit-%: ./batch/%.sub
	@bsub < ./batch/$*.sub
