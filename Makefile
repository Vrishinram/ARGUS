.PHONY: install test run demo lint init-db

install:
	pip install -r requirements.txt

init-db:
	python scripts/init_db.py

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

test:
	pytest tests/ -v

demo:
	python scripts/demo_attack_scenarios.py

lint:
	flake8 app tests --count --select=E9,F63,F7,F82 --show-source --statistics || true
