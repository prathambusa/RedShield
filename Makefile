.PHONY: install run gateway ui test eval docker clean

PYTHON ?= python3

install:
	$(PYTHON) -m pip install -r requirements.txt

run: gateway

gateway:
	uvicorn app.gateway.main:app --reload --host 127.0.0.1 --port 8000

ui:
	streamlit run main.py

test:
	pytest -q

eval:
	$(PYTHON) -m eval.run_eval --mode defended --out eval/reports/latest.md

docker:
	docker compose up --build

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ *.egg-info
