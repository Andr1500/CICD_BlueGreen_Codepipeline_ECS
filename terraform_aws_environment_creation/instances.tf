#This script is creating necessary infra with the necessary EC2 instances (Ubuntu or CentOS)
#and ECR for Gitlab CI/CD
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
  region = "eu-central-1"
}

data "aws_ami" "rhel8" {
  most_recent = true
  filter {
    name   = "name"
    values = ["RHEL-8*HVM-*Hourly*"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
  owners = ["309956199498"] # Red Hat
}

data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"]
}

resource "aws_ecr_repository" "repo" {
  name                 = "python-app2"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_instance" "ansible_RHEL8" {
  count                  = 0
  ami                    = data.aws_ami.rhel8.id
  instance_type          = "t3.micro"
  key_name               = "aws_key"
  vpc_security_group_ids = [aws_security_group.ansible_sg.id]

  tags = {
    Name  = "Server_RHEL8_${count.index + 1}"
    Owner = "Gitlab_CI"
  }
  connection {
    type        = "ssh"
    host        = self.public_ip
    user        = "ec2-user"
    private_key = file("/home/a1500/.ssh/id_rsa")
  }
}

resource "aws_instance" "ansible_ubuntu_linux" {
  count                  = 1
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  key_name               = "aws_key"
  vpc_security_group_ids = [aws_security_group.ansible_sg.id]

  tags = {
    Name  = "Server_Ubuntu_Linux_${count.index + 1}"
    Owner = "Gtlab_CI"
  }
  provisioner "file" {
    source      = "docker_aws_install.sh"
    destination = "/tmp/docker_aws_install.sh"
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/docker_aws_install.sh",
      "sudo /tmp/docker_aws_install.sh"
    ]
  }
  connection {
    type        = "ssh"
    host        = self.public_ip
    user        = "ubuntu"
    private_key = file("/home/a1500/.ssh/id_rsa")
  }
}

resource "aws_security_group" "ansible_sg" {
  name = "ansible-SG"

  dynamic "ingress" {
    for_each = ["80", "8080", "443", "22", "5000"]
    content {
      description = "Allow port HTTP"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
