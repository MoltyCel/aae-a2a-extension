PYTHON ?= python3.12
VENV   ?= .venv
PY      = $(VENV)/bin/python
VECTORS_COMMIT = 2f117799c604f258e67d5c13d69fea63881bdae0

.PHONY: install demo test vectors clean

$(PY):
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --require-hashes --no-deps -r requirements.txt

install: $(PY)

demo: $(PY)
	$(PY) -m aae_a2a.demo

test: $(PY)
	$(PY) -m pytest -q

# Run the section 5 verifier against MoltyCel/aae-conformance-vectors as well.
vectors: $(PY)
	@test -d .vectors || (git init -q .vectors && \
	  git -C .vectors fetch -q --depth 1 https://github.com/MoltyCel/aae-conformance-vectors $(VECTORS_COMMIT) && \
	  git -C .vectors checkout -q FETCH_HEAD)
	AAE_VECTORS_DIR=$(CURDIR)/.vectors $(PY) -m pytest -q

clean:
	rm -rf $(VENV) .vectors .pytest_cache
