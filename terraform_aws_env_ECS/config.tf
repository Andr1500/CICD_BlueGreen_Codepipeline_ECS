#This script is creating necessary infra with the necessary aws infrastructure, ECS,
#Codecommit, Codebuild, Codedeploy, Codepipeline, S3 bucket, SNS topic and ECR for Gitlab CI/CD
#
# For using ssh keys in this script we need to do:
#
# 1. Go to the necessary dir and generate keys:
# ssh-keygen -t rsa -b 2048
#
# 2. Upload the public key into AWS console -> Key Pairs:
# AWS console -> Key Pairs -> Actions -> Import key pair ->
#   ->(put the name "aws_key" and download the key) -> Import


provider "aws" {
  region = var.region
}

#######################
# VPC
#######################

locals {
  public_subnets = {
    "${var.region}a" = "10.10.101.0/24"
    "${var.region}b" = "10.10.102.0/24"
    "${var.region}c" = "10.10.103.0/24"
  }
  private_subnets = {
    "${var.region}a" = "10.10.201.0/24"
    "${var.region}b" = "10.10.202.0/24"
    "${var.region}c" = "10.10.203.0/24"
  }
}

resource "aws_vpc" "vpc" {
  cidr_block = "10.10.0.0/16"

  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.service_name}-vpc"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${var.service_name}-internet-gateway"
  }
}

resource "aws_subnet" "public" {
  count      = length(local.public_subnets)
  cidr_block = element(values(local.public_subnets), count.index)
  vpc_id     = aws_vpc.vpc.id

  map_public_ip_on_launch = true
  availability_zone       = element(keys(local.public_subnets), count.index)

  tags = {
    Name = "${var.service_name}-service-public"
  }
}

resource "aws_subnet" "private" {
  count      = length(local.private_subnets)
  cidr_block = element(values(local.private_subnets), count.index)
  vpc_id     = aws_vpc.vpc.id

  map_public_ip_on_launch = true
  availability_zone       = element(keys(local.private_subnets), count.index)

  tags = {
    Name = "${var.service_name}-service-private"
  }
}

resource "aws_default_route_table" "public" {
  default_route_table_id = aws_vpc.vpc.main_route_table_id

  tags = {
    Name = "${var.service_name}-public"
  }
}

resource "aws_route" "public_internet_gateway" {
  count                  = length(local.public_subnets)
  route_table_id         = aws_default_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id

  timeouts {
    create = "5m"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(local.public_subnets)
  subnet_id      = element(aws_subnet.public.*.id, count.index)
  route_table_id = aws_default_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${var.service_name}-private"
  }
}

resource "aws_route_table_association" "private" {
  count          = length(local.private_subnets)
  subnet_id      = element(aws_subnet.private.*.id, count.index)
  route_table_id = aws_route_table.private.id
}


resource "aws_eip" "nat" {
  vpc = true

  tags = {
    Name = "${var.service_name}-eip"
  }
}

resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.0.id

  tags = {
    Name = "${var.service_name}-nat-gw"
  }
}

resource "aws_route" "private_nat_gateway" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_gw.id

  timeouts {
    create = "5m"
  }
}

##########################
# Application Load Balanser
##########################

locals {
  target_groups = ["BLUE", "GREEN"]
}

#ALB security group
resource "aws_security_group" "alb" {
  name   = "${var.service_name}-allow-http"
  vpc_id = aws_vpc.vpc.id

  dynamic "ingress" {
    for_each = ["80", "443", "22", "5000"]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.service_name}-allow-http"
  }
}

# application load balanser
resource "aws_lb" "front" {
  name               = "${var.service_name}-service-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.alb.id}"]
  subnets            = aws_subnet.public.*.id

  tags = {
    Name = "${var.service_name}-service-alb"
  }
}

# ALB target group
resource "aws_lb_target_group" "target_group" {
  count = length(local.target_groups)
  name  = "${var.service_name}-tg-${element(local.target_groups, count.index)}"

  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc.id
  target_type = "instance"

  health_check {
    path = "/"
  }
}

#HTTPS ALB listener
resource "aws_lb_listener" "listener_https" {
  load_balancer_arn = aws_lb.front.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.issued.arn
  default_action {
    target_group_arn = aws_lb_target_group.target_group.0.arn
    type             = "forward"
  }
}

# HTTP ALB listener
resource "aws_lb_listener" "listener_http" {
  load_balancer_arn = aws_lb.front.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "redirect"
    target_group_arn = aws_lb_target_group.target_group.0.arn
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# get existing certificate data from ACM
data "aws_acm_certificate" "issued" {
  domain   = "*.${var.route53_hosted_zone_name}"
  statuses = ["ISSUED"]
}

# get data about DNS zone ID
data "aws_route53_zone" "zone" {
  name = var.route53_hosted_zone_name
}

# Route 53 A record
resource "aws_route53_record" "a_record" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = "${var.route53_subdomain_name}.${var.route53_hosted_zone_name}"
  type    = "A"
  alias {
    name                   = aws_lb.front.dns_name
    zone_id                = aws_lb.front.zone_id
    evaluate_target_health = true
  }
}

##########################
# Codecommit
##########################

resource "aws_codecommit_repository" "codecommit_repo" {
  repository_name = "from_gitlab"
  description     = "Clone git repo grom Gitlab"
}

#########################
# Codebuild
#########################

data "aws_iam_policy_document" "assume_by_codebuild" {
  statement {
    sid     = "AllowAssumeByCodebuild"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "codebuild" {
  name               = "${var.service_name}-codebuild"
  assume_role_policy = data.aws_iam_policy_document.assume_by_codebuild.json
}

data "aws_iam_policy_document" "codebuild" {
  statement {
    sid    = "AllowS3"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetBucketAcl",
      "s3:GetBucketLocation"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "AllowECR"
    effect = "Allow"

    actions = [
      "ecr:*"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "AWSKMSUse"
    effect = "Allow"

    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
      "kms:Encrypt",
      "kms:ReEncrypt*",
      "kms:Decrypt"
    ]

    resources = ["*"]
  }

  statement {
    sid       = "AllowECSDescribeTaskDefinition"
    effect    = "Allow"
    actions   = ["ecs:DescribeTaskDefinition"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowLogging"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "codebuild" {
  name   = "${var.service_name}-codebuild-policy"
  role   = aws_iam_role.codebuild.name
  policy = data.aws_iam_policy_document.codebuild.json
}

resource "aws_codebuild_project" "codebuild_project" {
  name         = "${var.service_name}-codebuild"
  description  = "Codebuild for the ECS Green/Blue ${var.service_name} app"
  service_role = aws_iam_role.codebuild.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/docker:18.09.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = true

    environment_variable {
      name  = "IMAGE_REPO_NAME"
      value = var.service_name
    }

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = var.aws_account_id
    }

    environment_variable {
      name  = "AWS_DEFAULT_REGION"
      value = var.region
    }

    environment_variable {
      name  = "IMAGE_TAG"
      value = "latest"
    }

    environment_variable {
      name  = "SERVICE_PORT"
      value = var.container_port
    }

    environment_variable {
      name  = "MEMORY_RESV"
      value = var.memory_reserv
    }
  }

  source {
    type     = "CODECOMMIT"
    location = var.codecommit_repo
  }
}

###########################
# Codedeploy
##########################

data "aws_iam_policy_document" "assume_by_codedeploy" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codedeploy.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "codedeploy" {
  name               = "${var.service_name}-codedeploy"
  assume_role_policy = data.aws_iam_policy_document.assume_by_codedeploy.json
}

data "aws_iam_policy_document" "codedeploy" {
  statement {
    sid    = "AllowLoadBalancingAndECSModifications"
    effect = "Allow"

    actions = [
      "ecs:CreateTaskSet",
      "ecs:DeleteTaskSet",
      "ecs:DescribeServices",
      "ecs:UpdateServicePrimaryTaskSet",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyRule",
      "lambda:InvokeFunction",
      "cloudwatch:DescribeAlarms",
      "sns:Publish",
      "s3:GetObject",
      "s3:GetObjectMetadata",
      "s3:GetObjectVersion"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "AllowPassRole"
    effect = "Allow"

    actions = ["iam:PassRole"]

    resources = [
      "${aws_iam_role.execution_role.arn}",
      "${aws_iam_role.task_role.arn}",
    ]
  }
}

resource "aws_iam_role_policy" "codedeploy" {
  role   = aws_iam_role.codedeploy.name
  policy = data.aws_iam_policy_document.codedeploy.json
}

resource "aws_codedeploy_app" "codedeploy_app" {
  compute_platform = "ECS"
  name             = "${var.service_name}-service-deploy"
}

resource "aws_codedeploy_deployment_group" "deployment_group" {
  app_name               = aws_codedeploy_app.codedeploy_app.name
  deployment_group_name  = "${var.service_name}-service-deploy-group"
  deployment_config_name = "CodeDeployDefault.ECSAllAtOnce"
  service_role_arn       = aws_iam_role.codedeploy.arn

  blue_green_deployment_config {
    deployment_ready_option {
      action_on_timeout = "CONTINUE_DEPLOYMENT"
    }

    terminate_blue_instances_on_deployment_success {
      action                           = "TERMINATE"
      termination_wait_time_in_minutes = 10
    }
  }

  ecs_service {
    cluster_name = aws_ecs_cluster.ecs_cluster.name
    service_name = aws_ecs_service.ecs_service.name
  }

  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "BLUE_GREEN"
  }

  load_balancer_info {
    target_group_pair_info {
      prod_traffic_route {
        listener_arns = ["${aws_lb_listener.listener_https.arn}"]
      }

      target_group {
        name = aws_lb_target_group.target_group.*.name[0]
      }

      target_group {
        name = aws_lb_target_group.target_group.*.name[1]
      }
    }
  }
}

###########################
# Codepipeline
###########################

resource "aws_s3_bucket" "codepipeline_bucket" {
  bucket        = var.s3_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "versioning_example" {
  bucket = aws_s3_bucket.codepipeline_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "pipeline" {
  bucket = aws_s3_bucket.codepipeline_bucket.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "${var.service_name}Codepipeline",
  "Statement": [
        {
            "Sid": "DenyUnEncryptedObjectUploads",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${var.s3_bucket_name}/*",
            "Condition": {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": "aws:kms"
                }
            }
        },
        {
            "Sid": "DenyInsecureConnections",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::${var.s3_bucket_name}/*",
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
POLICY
}

data "aws_iam_policy_document" "assume_by_pipeline" {
  statement {
    sid     = "AllowAssumeByPipeline"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codepipeline.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "pipeline" {
  name               = "${var.service_name}-pipeline-ecs-service-role"
  assume_role_policy = data.aws_iam_policy_document.assume_by_pipeline.json
}

data "aws_iam_policy_document" "pipeline" {
  statement {
    sid    = "AllowS3"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:PutObject",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "AllowECR"
    effect = "Allow"

    actions   = ["ecr:DescribeImages"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCodebuild"
    effect = "Allow"

    actions = [
      "codebuild:BatchGetBuilds",
      "codebuild:StartBuild"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCodecommit"
    effect = "Allow"

    actions = [
      "codecommit:*"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ConnectionsFullAccess"
    effect = "Allow"
    actions = [
      "codestar-connections:CreateConnection",
      "codestar-connections:DeleteConnection",
      "codestar-connections:UseConnection",
      "codestar-connections:GetConnection",
      "codestar-connections:ListConnections",
      "codestar-connections:TagResource",
      "codestar-connections:ListTagsForResource",
      "codestar-connections:UntagResource"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCodedepoloy"
    effect = "Allow"

    actions = [
      "codedeploy:CreateDeployment",
      "codedeploy:GetApplication",
      "codedeploy:GetApplicationRevision",
      "codedeploy:GetDeployment",
      "codedeploy:GetDeploymentConfig",
      "codedeploy:RegisterApplicationRevision"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowResources"
    effect = "Allow"

    actions = [
      "elasticbeanstalk:*",
      "ec2:*",
      "elasticloadbalancing:*",
      "autoscaling:*",
      "cloudwatch:*",
      "s3:*",
      "sns:*",
      "cloudformation:*",
      "rds:*",
      "sqs:*",
      "ecs:*",
      "opsworks:*",
      "devicefarm:*",
      "servicecatalog:*",
      "iam:PassRole"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "pipeline" {
  name   = "${var.service_name}-pipeline-ecs-policy"
  role   = aws_iam_role.pipeline.name
  policy = data.aws_iam_policy_document.pipeline.json
}

resource "aws_codepipeline" "codepipeline" {
  name     = "${var.service_name}-pipeline"
  role_arn = aws_iam_role.pipeline.arn
  depends_on = [
    aws_codedeploy_deployment_group.deployment_group,
    aws_codecommit_repository.codecommit_repo
  ]

  artifact_store {
    location = aws_s3_bucket.codepipeline_bucket.bucket
    type     = "S3"
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeCommit"
      input_artifacts  = []
      version          = "1"
      output_artifacts = ["SourceArtifact"]

      configuration = {
        RepositoryName       = "from_gitlab"
        BranchName           = "deploy_to_codecommit"
        PollForSourceChanges = true
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceArtifact"]
      output_artifacts = ["BuildArtifact"]

      configuration = {
        ProjectName = "${aws_codebuild_project.codebuild_project.name}"
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "ExternalDeploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "CodeDeployToECS"
      input_artifacts = ["BuildArtifact"]
      version         = "1"

      configuration = {
        ApplicationName                = aws_codedeploy_app.codedeploy_app.name
        DeploymentGroupName            = aws_codedeploy_deployment_group.deployment_group.deployment_group_name
        TaskDefinitionTemplateArtifact = "BuildArtifact"
        TaskDefinitionTemplatePath     = "taskdef.json"
        AppSpecTemplateArtifact        = "BuildArtifact"
        AppSpecTemplatePath            = "appspec.yml"
      }
    }
  }
}

#############################
# Elastic Container Registry
#############################

data "aws_iam_policy_document" "assume_by_ecr" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecr" {
  name               = "${var.service_name}-ECR-ReadForECSServiceAccount"
  assume_role_policy = data.aws_iam_policy_document.assume_by_ecr.json
}

resource "aws_ecr_repository" "this" {
  name         = var.service_name
  force_delete = true

}

resource "aws_ecr_repository_policy" "ecr_policy" {
  repository = aws_ecr_repository.this.name
  policy     = <<EOF
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Sid": "${var.service_name}",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "${aws_iam_role.ecr.arn}",
          "${aws_iam_role.codebuild.arn}",
          "${aws_iam_role.codedeploy.arn}",
          "${aws_iam_role.pipeline.arn}"
        ]
      },
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:DescribeImages",
        "ecr:DescribeRepositories",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetLifecyclePolicy",
        "ecr:GetLifecyclePolicyPreview",
        "ecr:GetRepositoryPolicy",
        "ecr:ListImages"
      ]
    }
  ]
}
EOF
}

###################################
# Elastic Contailer Service
###################################

data "aws_iam_policy_document" "assume_by_ecs" {
  statement {
    sid     = "AllowAssumeByEcsTasks"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "execution_role" {
  statement {
    sid    = "AllowECRLogging"
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = ["*"]
  }
}

data "aws_iam_policy_document" "task_role" {
  statement {
    sid    = "AllowDescribeCluster"
    effect = "Allow"

    actions = ["ecs:DescribeClusters"]

    resources = ["${aws_ecs_cluster.ecs_cluster.arn}"]
  }
}

resource "aws_iam_role" "execution_role" {
  name               = "${var.service_name}_ecsTaskExecutionRole"
  assume_role_policy = data.aws_iam_policy_document.assume_by_ecs.json
}

resource "aws_iam_role_policy" "execution_role" {
  name   = "${var.service_name}_ecs_exec_policy"
  role   = aws_iam_role.execution_role.name
  policy = data.aws_iam_policy_document.execution_role.json
}

resource "aws_iam_role" "task_role" {
  name               = "${var.service_name}_ecsTaskRole"
  assume_role_policy = data.aws_iam_policy_document.assume_by_ecs.json
}

resource "aws_iam_role_policy" "task_role" {
  name   = "${var.service_name}_ecs_task_policy"
  role   = aws_iam_role.task_role.name
  policy = data.aws_iam_policy_document.task_role.json
}

resource "aws_ecs_cluster" "ecs_cluster" {
  name = "${var.service_name}_cluster"
}

resource "aws_security_group" "ecs" {
  name   = "${var.service_name}-allow-ecs"
  vpc_id = aws_vpc.vpc.id

  ingress {
    description     = "Ingress"
    from_port       = 0
    protocol        = "-1"
    to_port         = 0
    security_groups = ["${aws_security_group.alb.id}"]
  }

  egress {
    description = "Egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ECS Service
resource "aws_ecs_service" "ecs_service" {
  name            = var.service_name
  task_definition = aws_ecs_task_definition.task_definition.id
  cluster         = aws_ecs_cluster.ecs_cluster.arn

  load_balancer {
    target_group_arn = aws_lb_target_group.target_group.0.arn
    container_name   = var.service_name
    container_port   = var.container_port
  }

  launch_type                        = "EC2"
  desired_count                      = 1
  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  deployment_controller {
    type = "CODE_DEPLOY"
  }

  depends_on = [aws_lb_listener.listener_https]
}

# ECS Task Definition
resource "null_resource" "deregister_task_definition" {
  provisioner "local-exec" {
    command = "/bin/bash deregister_task_definition.sh"
    environment = {
      TASK_NAME = format("%s", var.service_name)
    }
  }
}

resource "aws_ecs_task_definition" "task_definition" {
  family                   = var.service_name
  execution_role_arn       = aws_iam_role.execution_role.arn
  task_role_arn            = aws_iam_role.task_role.arn
  network_mode             = "bridge"
  requires_compatibilities = ["EC2"]
  depends_on               = [null_resource.deregister_task_definition]
  container_definitions    = <<DEFINITION
[
   {
      "portMappings": [
        {
          "hostPort": 0,
          "protocol": "tcp",
          "containerPort": ${var.container_port}
        }
      ],
      "environment": [
        {
          "name": "PORT",
          "value": "${var.container_port}"
        },
        {
          "name" : "APP_NAME",
          "value": "${var.service_name}"
        }
      ],
      "memoryReservation" : ${var.memory_reserv},
      "image": "${var.service_container}",
      "name": "${var.service_name}"
    }
]
DEFINITION
}

#################################
# Launch EC2 instance config
#################################

data "aws_ami" "latest-ecs" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-*-amazon-ecs-optimized"]
  }
}

resource "aws_launch_configuration" "launch_config" {
  name                 = "ECS-Instance-${var.service_name}"
  image_id             = data.aws_ami.latest-ecs.id
  instance_type        = var.instance_type
  iam_instance_profile = aws_iam_instance_profile.ecs-instance-profile.id

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 15
    delete_on_termination = true
  }

  lifecycle {
    create_before_destroy = true
  }

  security_groups             = ["${aws_security_group.ecs.id}", "${aws_security_group.alb.id}"]
  associate_public_ip_address = "true"
  key_name                    = var.ecs_key_pair_name
  user_data = templatefile("ec2_user_data.tpl", {
    service_name = var.service_name
  })
}

resource "aws_autoscaling_group" "asg" {
  name                 = "${var.service_name}-ecs-autoscaling-group"
  max_size             = 2
  min_size             = 1
  desired_capacity     = 1
  vpc_zone_identifier  = aws_subnet.public.*.id
  launch_configuration = aws_launch_configuration.launch_config.name
  health_check_type    = "ELB"

  tag {
    key                 = "Name"
    value               = "ECS-Instance-${var.service_name}-service"
    propagate_at_launch = true
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role" "ecs-instance-role" {
  name               = "${var.service_name}-ecs-instance-role"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.ecs-instance-policy.json
}

data "aws_iam_policy_document" "ecs-instance-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "ecs-instance-role-attachment" {
  role       = aws_iam_role.ecs-instance-role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "ecs-instance-profile" {
  name = "${var.service_name}-ecs-instance-profile"
  path = "/"
  role = aws_iam_role.ecs-instance-role.id
}

############################
# SNS topic and subscription
############################

#Create SNS topic for notifications from CodeDeploy
resource "aws_sns_topic" "sns_topic" {
  name = "Codepipeline_SNS_topic"
}
#Creation of SNS subscription
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.sns_topic.arn
  protocol  = "email"
  endpoint  = "a1500@tutanota.com"
}

#policy for SNS topic
data "aws_iam_policy_document" "notif_access" {
  statement {
    actions = ["sns:Publish"]

    principals {
      type        = "Service"
      identifiers = ["codestar-notifications.amazonaws.com"]
    }
    resources = [aws_sns_topic.sns_topic.arn]
  }
}

#sns notification policy attachment
resource "aws_sns_topic_policy" "default" {
  arn    = aws_sns_topic.sns_topic.arn
  policy = data.aws_iam_policy_document.notif_access.json
}

#Notification rule for Codedebuild
resource "aws_codestarnotifications_notification_rule" "codedeploy" {
  detail_type    = "BASIC"
  event_type_ids = ["codebuild-project-build-phase-failure", "codebuild-project-build-phase-success"]

  name     = "codebuild_commits"
  resource = aws_codebuild_project.codebuild_project.arn

  target {
    address = aws_sns_topic.sns_topic.arn
  }
}

#Notification rule for Codedeploy
resource "aws_codestarnotifications_notification_rule" "commits" {
  detail_type    = "BASIC"
  event_type_ids = ["codedeploy-application-deployment-failed", "codedeploy-application-deployment-succeeded"]

  name     = "codedeploy_commits"
  resource = aws_codedeploy_app.codedeploy_app.arn

  target {
    address = aws_sns_topic.sns_topic.arn
  }
}
