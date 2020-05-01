VIRTUAL_ENV ?= venv

setup-and-test: python-venv test

analyze-code: python-venv analyze


clean-all:
	rm -rf venv

analyze:
	. ${VIRTUAL_ENV}/bin/activate && \
	bash scripts/analyze.sh -d "core scripts tests tools" -t tests

python-venv:
	python3.6 -v venv ${VIRTUAL_ENV}
	. ${VIRTUAL_ENV}/bin/python
	python3.6 -m pip install -r requirements.txt

test:
	. ${VIRTUAL_ENV}/bin/activate && \
	coverage run -m pytest -vv --cov-report xml tests/ && \
	coverage html
