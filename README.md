# Juice Shop DevSecOps Pipeline

A CI/CD security pipeline integrating SAST, SCA, and DAST
using Jenkins and Docker.

## Technologies

- Jenkins
- Docker and Docker Compose
- Semgrep OSS
- OWASP Dependency-Check
- npm audit
- OWASP ZAP
- Python
- GitHub

## Project Structure

- Jenkinsfile: CI/CD pipeline definition
- security-gate/: Automated vulnerability evaluation
- reports/: Generated security reports

## Security Testing

| Category | Tool |
|---|---|
| SAST | Semgrep OSS |
| SCA | OWASP Dependency-Check |
| SCA | npm audit |
| DAST | OWASP ZAP |

## Security Gate Policy

| Severity | Action |
|---|---|
| Critical | Block build |
| High | Block build |
| Moderate | Warning |
| Low | Informational |

## Target Application

OWASP Juice Shop:
https://github.com/juice-shop/juice-shop
