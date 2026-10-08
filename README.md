# Vulnerable Notes - TP DevSecOps 1 (SAST / SCA)

Application Flask **volontairement vulnérable** pour le TP d'analyse statique (Bandit)
et d'analyse des dépendances (OWASP Dependency-Check).

**Ne jamais déployer en production.**

## Prérequis

- Git
- Docker

## Démonstration avant / après (Docker Compose)

Deux projets côte à côte :

| Service | Dossier | Port hôte | Contenu |
|---------|---------|-----------|---------|
| `before` | [`before/`](before/) | **5000** | SQLi + XSS + PyYAML 5.3.1 |
| `after`  | [`after/`](after/)   | **5001** | correctifs SAST + PyYAML 6.0.2 |

```bash
docker compose up --build -d
```

Comparer les mêmes payloads :

```bash
# --- Injection SQL ---
# BEFORE (vulnérable) : renvoie admin + alice
curl -s --get "http://localhost:5000/user" --data-urlencode "name=' OR '1'='1"
echo
# AFTER (corrigé) : pas d'injection
curl -s --get "http://localhost:5001/user" --data-urlencode "name=' OR '1'='1"
echo

# --- XSS ---
# BEFORE : <script> brut
curl -s --get "http://localhost:5000/hello" \
  --data-urlencode "name=<script>alert(1)</script>"
echo
# AFTER : échappé (&lt;script&gt;)
curl -s --get "http://localhost:5001/hello" \
  --data-urlencode "name=<script>alert(1)</script>"
echo
```

Dans le navigateur :

- BEFORE XSS : http://localhost:5000/hello?name=%3Cscript%3Ealert(1)%3C/script%3E
- AFTER XSS : http://localhost:5001/hello?name=%3Cscript%3Ealert(1)%3C/script%3E

Arrêt :

```bash
docker compose down
```

## Démarrer une seule image (racine)

```bash
docker build -t vulnerable-notes .
docker run --rm -p 5000:5000 --name notes vulnerable-notes
```

## Scanners (voir `rapport.md` pour le détail)

```bash
mkdir -p reports

# SAST - Bandit
docker run --rm -v "$PWD":/src python:3.11-slim sh -c \
  "pip install -q bandit && bandit -r /src/app.py -f txt"

# SCA - OWASP Dependency-Check (premier lancement long sans clé NVD)
docker run --rm \
  -v "$PWD":/src \
  -v "$PWD/reports":/report \
  -v "$PWD/.odc-data":/usr/share/dependency-check/data \
  owasp/dependency-check \
  --scan /src \
  --enableExperimental \
  --format HTML --format JSON \
  --out /report \
  --project vulnerable-notes
```

Le rapport de TP est dans [`rapport.md`](rapport.md).
