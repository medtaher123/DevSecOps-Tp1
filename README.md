# Vulnerable Notes - TP DevSecOps 1 (SAST / SCA)

Application Flask **volontairement vulnérable** pour le TP d'analyse statique (Bandit)
et d'analyse des dépendances (OWASP Dependency-Check).

**Ne jamais déployer en production.**

## Prérequis

- Git
- Docker

## Démarrer l'application

```bash
docker build -t vulnerable-notes .
docker run --rm -p 5000:5000 --name notes vulnerable-notes
```

Dans un autre terminal :

```bash
# Injection SQL - retourne tous les utilisateurs
curl -s --get "http://localhost:5000/user" --data-urlencode "name=' OR '1'='1"

# XSS réfléchi - le <script> est renvoyé tel quel
curl -s --get "http://localhost:5000/hello" \
  --data-urlencode "name=<script>alert(1)</script>"
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
