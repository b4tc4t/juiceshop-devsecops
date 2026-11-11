
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                echo 'Repository checked out successfully.'
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
    }

    post {
        always {
            echo 'DevSecOps pipeline execution completed.'
        }
    }
}
