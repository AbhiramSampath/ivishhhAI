provider "aws" {
  region = var.aws_region
}

# -------------------
# VPC
# -------------------
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  name    = "verbx-vpc"
  cidr    = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  tags = {
    Name = "verbx-vpc"
  }
}

# -------------------
# S3 Bucket for AI Models
# -------------------
resource "aws_s3_bucket" "ai_model_bucket" {
  bucket = "verbx-ai-models-${var.env}"
  force_destroy = true

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }

  lifecycle_rule {
    enabled = true
    noncurrent_version_expiration {
      days = 30
    }
  }

  tags = {
    Purpose = "Store ML/DL model files"
    Environment = var.env
  }
}

# -------------------
# EC2 Instance for STT/TTS/Model Serving
# -------------------
resource "aws_instance" "ai_worker" {
  ami                    = var.ec2_ami
  instance_type          = var.ec2_type
  subnet_id              = module.vpc.private_subnets[0]
  vpc_security_group_ids = [aws_security_group.ai_sg.id]
  key_name               = var.key_pair

  tags = {
    Name = "ivish-ai-worker"
  }

  user_data = file("scripts/deploy_ai_worker.sh") # Your docker-compose or Whisper/Sarvam startup script
}

resource "aws_security_group" "ai_sg" {
  name        = "ai-worker-sg"
  description = "Allow internal AI communication"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "App ports (FastAPI, Redis, Mongo)"
    from_port   = 8000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ai-worker-sg"
  }
}

# -------------------
# Redis (Elasticache)
# -------------------
module "redis" {
  source  = "cloudposse/elasticache-redis/aws"
  name    = "verbx-redis"
  vpc_id  = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_size     = 1
  instance_type    = "cache.t3.micro"
  apply_immediately = true
}

# -------------------
# MongoDB (Self-hosted or DocumentDB)
# -------------------
resource "aws_db_instance" "mongodb" {
  identifier         = "verbx-mongodb"
  engine             = "postgres"
  instance_class     = "db.t3.micro"
  allocated_storage  = 20
  username           = var.db_user
  password           = var.db_pass
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.mongo_subnet_group.name
  vpc_security_group_ids = [aws_security_group.ai_sg.id]
  skip_final_snapshot = true

  tags = {
    Name = "verbx-mongo"
  }
}

resource "aws_db_subnet_group" "mongo_subnet_group" {
  name       = "verbx-mongo-subnets"
  subnet_ids = module.vpc.private_subnets
}

# -------------------
# Outputs
# -------------------
output "ai_worker_ip" {
  value = aws_instance.ai_worker.public_ip
}

output "redis_endpoint" {
  value = module.redis.endpoint
}

output "s3_model_bucket" {
  value = aws_s3_bucket.ai_model_bucket.bucket
}
