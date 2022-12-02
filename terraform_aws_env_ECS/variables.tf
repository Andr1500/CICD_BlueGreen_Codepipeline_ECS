#variables
variable "region" {
  default = "eu-central-1"
}

variable "ecs_key_pair_name" {
  default = "aws_key"
}

variable "aws_account_id" {
  default = "138161713046"
}

variable "service_name" {
  type    = string
  default = "flask-app"
}

variable "service_container" {
  default = "public.ecr.aws/sam/emulation-python3.9:latest"
}

variable "container_port" {
  default = "5000"
}

variable "memory_reserv" {
  default = "100"
}

variable "codecommit_repo" {
  default = "https://git-codecommit.eu-central-1.amazonaws.com/v1/repos/codecommit_repo"
}

variable "s3_bucket_name" {
  default = "codepipeline-bucket-pipeline-files"
}

variable "instance_type" {
  default = "t3.micro"
}

variable "route53_hosted_zone_name" {
  default = "an1500.click"
}

variable "route53_subdomain_name" {
  default = "flaskapp"
}
