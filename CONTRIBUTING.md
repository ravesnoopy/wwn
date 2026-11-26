# Contribuir
1. Haz fork y crea una rama.
2. `python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt`
3. `.venv/bin/python -m pytest -q` debe pasar antes de abrir un PR.
4. Reglas: sin credenciales en el repo, sin funciones anunciadas que no estén implementadas, toda acción administrativa auditada, todo clasificado por heurística debe etiquetarse "estimado".
5. Commits convencionales (`feat:`, `fix:`, `docs:`) y entrada en `CHANGELOG.md`.
