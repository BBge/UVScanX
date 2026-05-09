.PHONY: help rules rag-index smoke test firmware-smoke clean distclean

help:
	@echo "Targets: rules rag-index smoke test firmware-smoke clean distclean"

rules:
	python3 -m uvscanx rules extract --out data/rules/api_rules.json

rag-index:
	python3 -m uvscanx rag index --docs data/rag/documents --out data/rag/index

smoke: rules
	./scripts/build_synthetic.sh
	python3 -m uvscanx scan examples/synthetic/bin --out runs/smoke --firmware-id synthetic-regression --engine datalog
	python3 -m uvscanx report runs/smoke/summary.json

test:
	@if python3 -c "import pytest" >/dev/null 2>&1; then python3 -m pytest -q tests; else python3 tests/run_smoke.py; fi

firmware-smoke:
	python3 -m uvscanx firmware download --profile smoke --out data/firmware
	python3 -m uvscanx firmware unpack data/firmware --out data/rootfs
	python3 -m uvscanx tpc identify data/rootfs --out runs/tpc-smoke --limit 50
	python3 -m uvscanx scan data/rootfs --out runs/firmware-smoke --firmware-id smoke --tpc-summary runs/tpc-smoke/tpc_summary.json --max-binaries 100 --priority-only

clean:
	rm -rf runs .pytest_cache examples/synthetic/bin
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

distclean: clean
	rm -rf data/firmware data/rootfs data/rootfs-* tools artifacts archive_unrelated
	rm -rf data/rag/index
	mkdir -p data/rag/index && touch data/rag/index/.gitkeep
