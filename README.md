# Python Flask - Demo Web Application

This is a simple Python Flask web application. The app is based on this repo: https://github.com/benc-uk/python-demoapp. The app provides system information and a realtime monitoring screen with dials showing CPU, memory, IO and process information.

The app has been designed with cloud native demos & containers in mind, in order to provide a real working application for deployment, something more than "hello-world" but with the minimum of pre-reqs. It is not intended as a complete example of a fully functioning architecture or complex software design.

Typical uses would be deployment to Kubernetes, demos of Docker, CI/CD (build pipelines are provided), deployment to cloud (AWS) monitoring, auto-scaling

## Screenshot

![screen](images/python_flask_app.png)


## Building & Running

### Pre-reqs

- Be using Linux, WSL or MacOS, with bash, make etc
- [Python 3.8+](https://www.python.org/downloads/) - for running locally, linting, running tests etc
- [Docker](https://docs.docker.com/get-docker/) - for running as a container, or image build and push
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) - for deployment to AWS

Clone the project to any directory where you do development work

```
git clone https://gitlab.com/Andr1500/cicd_bluegreen_codepipeline_ecs.git
```

### Makefile

A standard GNU Make file is provided to help with running and building locally.

```text
help                 💬 This help message
lint                 🔎 Lint & format, will not fix but sets exit code on error
lint-fix             📜 Lint & format, will try to fix errors and modify code
image                🔨 Build container image from Dockerfile
push                 📤 Push container image to registry
run                  🏃 Run the server locally using Python & Flask
deploy               🚀 Deploy to Azure Web App
undeploy             💀 Remove from Azure
test                 🎯 Unit tests for Flask app
test-report          🎯 Unit tests for Flask app (with report output)
test-api             🚦 Run integration API tests, server must be running
clean                🧹 Clean up project
```

The app runs under Flask and listens on port 5000 by default, this can be changed with the `PORT` environmental variable.

# Creation of AWS infrastructure (ECR, CodeCommit, CodeBuild, CodeDeploy, CodePipeline, SNS topic, S3 bucket, ECS) with Terraform

Go to terraform_aws_env_ECS/ and build AWS environment:

set AWS credentials, credentials can be exported as environment variables:
```
export AWS_SECRET_ACCESS_KEY="SECRET_KEY"
export AWS_ACCESS_KEY_ID="ACCES_KEY"
```
run ```terraform init```
if everything is ok, run ```terraform plan``` and ```terraform apply```
when infrastructure will not be necessary, run ```terraform destroy```

# Gitlab pipeline

A working set of CI release Gitlab workflows are provided in .gitlab-ci.yml.

Gitlab pipeline stages:

- **test** Making test of the app
- **deploy** Clone existing repo to AWS Codecommit repo.

# Gitlab Variables

Add variables into Gitlab repo Settings -> CI/CD -> Variables

![Gitlab Variables](images/gitlab_variables.png)

# AWS pipeline

Main part of CI/CD pipeline is done by AWS Codepipeline with stages:
Source - CodeCommit,
Build  - CodeBuild,
Deploy - CodeDeploy.
Application deploy on Elastic Container Service. SNS topic is configured for receiving emails about success or fail stages of CodeBuid and CodeDeploy. S3 bucket is necessary for storing source and buid artifacts which are necesary for CodePipeline execution.

![AWS pipeline](images/aws_pipeline.png)

### [Gitlab pipeline](https://gitlab.com/Andr1500/cicd_bluegreen_codepipeline_ecs/-/pipelines)
