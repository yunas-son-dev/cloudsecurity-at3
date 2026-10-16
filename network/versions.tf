terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state (optional). Create the S3 bucket first, then uncomment and run: terraform init -migrate-state
  # backend "s3" {
  #   bucket       = "namawin-tfstate-<account-id>"
  #   key          = "network/terraform.tfstate"
  #   region       = "ap-southeast-2"
  #   use_lockfile = true
  #   encrypt      = true
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project   = "namawin"
      owner     = "yuna"
      component = "network"
    }
  }
}
