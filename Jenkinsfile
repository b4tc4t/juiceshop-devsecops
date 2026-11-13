
pipeline {
    agent any

    options {
        disableConcurrentBuilds()
    }

    parameters {
        booleanParam(
            name: 'RUN_FULL_DAST',
            defaultValue: false,
            description: 'Run ZAP Full Scan (active security testing)'
        )
    }

    environment {
        JUICE_SHOP_URL = 'http://127.0.0.1:3001'
        JUICE_SHOP_CONTAINER = 'juice-shop-ci'
    }

    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out DevSecOps repository'
                sh 'git rev-parse --short HEAD'
                sh 'ls -la'
            }
        }

        stage('Verify Docker') {
            steps {
                sh 'docker --version'
                sh 'docker compose version'
                sh 'docker ps'
            }
        }

        stage('Docker Smoke Test') {
            steps {
                sh 'docker run --rm hello-world'
            }
        }

        stage('Clone OWASP Juice Shop') {
            steps {
                sh '''
                    rm -rf juice-shop

                    git clone --depth 1 \
                        https://github.com/juice-shop/juice-shop.git \
                        juice-shop

                    mkdir -p juice-shop/reports
                '''
            }
        }

        stage('SCA - npm audit') {
            steps {
                sh '''
                    REPORT="$WORKSPACE/juice-shop/reports/npm-audit-report.json"

                    set +e
                    docker run --rm \
                        -v "$WORKSPACE/juice-shop:/src" \
                        -w /src \
                        node:22-bookworm \
                        npm audit --json > "$REPORT"
                    AUDIT_EXIT=$?
                    set -e

                    echo "npm audit exit code: $AUDIT_EXIT"

                    python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    report = json.load(f)
assert "metadata" in report
assert "vulnerabilities" in report["metadata"]
print("npm audit report generated successfully")
print("Vulnerability summary:",
      report["metadata"]["vulnerabilities"])
' "$REPORT"
                '''
            }
        }

        stage('SAST - Semgrep') {
            steps {
                sh '''
                    docker pull semgrep/semgrep

                    docker run --rm \
                        -v "$WORKSPACE/juice-shop:/src" \
                        semgrep/semgrep \
                        semgrep scan \
                        --config auto \
                        --json \
                        --output /src/reports/semgrep-report.json \
                        /src
                '''
            }
        }

        stage('Start Juice Shop for DAST') {
            steps {
                sh '''
                    docker rm -f "$JUICE_SHOP_CONTAINER" \
                        >/dev/null 2>&1 || true

                    docker pull bkimminich/juice-shop

                    docker run -d \
                        --name "$JUICE_SHOP_CONTAINER" \
                        -p 127.0.0.1:3001:3000 \
                        bkimminich/juice-shop

                    echo "Waiting for Juice Shop..."

                    for i in $(seq 1 60); do
                        if curl -fsS "$JUICE_SHOP_URL" \
                            >/dev/null; then
                            echo "Juice Shop is ready!"
                            exit 0
                        fi
                        sleep 2
                    done

                    echo "Juice Shop failed to start"
                    exit 1
                '''
            }
        }

        stage('DAST - ZAP Baseline') {
            steps {
                sh '''
                    docker pull ghcr.io/zaproxy/zaproxy:stable

                    chmod 777 "$WORKSPACE/juice-shop/reports"

                    set +e
                    docker run --rm \
                        --network host \
                        -v "$WORKSPACE/juice-shop/reports:/zap/wrk/:rw" \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py \
                        -t "$JUICE_SHOP_URL" \
                        -J zap-baseline-report.json \
                        -r zap-baseline-report.html

                    ZAP_EXIT=$?
                    set -e

                    echo "ZAP Baseline exit code: $ZAP_EXIT"

                    test -s juice-shop/reports/zap-baseline-report.json
                    test -s juice-shop/reports/zap-baseline-report.html
                '''
            }
        }

        stage('DAST - ZAP Full Scan') {
            when {
                expression {
                    return params.RUN_FULL_DAST
                }
            }

            steps {
                sh '''
                    set +e
                    docker run --rm \
                        --network host \
                        -v "$WORKSPACE/juice-shop/reports:/zap/wrk/:rw" \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-full-scan.py \
                        -t "$JUICE_SHOP_URL" \
                        -J zap-full-report.json \
                        -r zap-full-report.html

                    ZAP_EXIT=$?
                    set -e

                    echo "ZAP Full Scan exit code: $ZAP_EXIT"

                    test -s juice-shop/reports/zap-full-report.json
                    test -s juice-shop/reports/zap-full-report.html
                '''
            }
        }

        stage('Archive Security Reports') {
            steps {
                archiveArtifacts(
                    artifacts: 'juice-shop/reports/*',
                    fingerprint: true,
                    allowEmptyArchive: true
                )
            }
        }
    }

    post {
        always {
            echo 'Cleaning up Juice Shop container...'
            sh '''
                docker rm -f "$JUICE_SHOP_CONTAINER" \
                    >/dev/null 2>&1 || true
            '''
            echo 'DevSecOps pipeline execution completed.'
        }
    }
}
