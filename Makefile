.PHONY: install run gateway ui test eval red-team docker clean

PYTHON ?= .venv/bin/python3

install:
	$(PYTHON) -m pip install -r requirements.txt

run: gateway

gateway:
	.venv/bin/uvicorn app.gateway.main:app --reload --reload-dir app --host 127.0.0.1 --port 8000

ui:
	.venv/bin/streamlit run main.py

test:
	.venv/bin/pytest -q

LIVE ?=
MODE ?= defended

eval:
	$(PYTHON) -m eval.run_eval --mode $(MODE) --out eval/reports/latest.md $(if $(LIVE),--live)

SEEDS ?=
MUTATIONS ?= 8
TAXONOMY ?=
STUB ?=

red-team:
	$(PYTHON) -m eval.run_red_team \
		--mutations-per-seed $(MUTATIONS) \
		--out eval/reports/red_team.md \
		$(if $(SEEDS),--limit $(SEEDS)) \
		$(if $(TAXONOMY),--taxonomy $(TAXONOMY)) \
		$(if $(STUB),--stub) \
		$(if $(PROPOSE),--propose-rules)

docker:
	docker compose up --build

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ *.egg-info
