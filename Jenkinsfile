
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out DevSecOps repository'
                sh 'pwd'
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

        stage('Archive SAST Report') {
            steps {
                archiveArtifacts(
                    artifacts: 'juice-shop/reports/semgrep-report.json',
                    fingerprint: true
                )
            }
        }
    }

    post {
        always {
            echo 'DevSecOps pipeline execution completed.'
        }
    }
}

