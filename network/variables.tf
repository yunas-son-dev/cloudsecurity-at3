variable "region" {
  description = "AWS region for the whole project."
  type        = string
  default     = "ap-southeast-2"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "namawin"
}

variable "vpc_cidr" {
  description = "VPC CIDR block (AT2 section 7.1)."
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Public subnets (ALB, NAT gateways), one per AZ."
  type        = list(string)
  default     = ["10.20.0.0/24", "10.20.1.0/24"]
}

variable "app_subnet_cidrs" {
  description = "Private application subnets (Elastic Beanstalk instances, Secrets Manager endpoint), one per AZ."
  type        = list(string)
  default     = ["10.20.10.0/24", "10.20.11.0/24"]
}

variable "db_subnet_cidrs" {
  description = "Private database subnets (RDS), one per AZ. No internet route."
  type        = list(string)
  default     = ["10.20.20.0/24", "10.20.21.0/24"]
}

variable "nat_gateway_count" {
  description = "1 saves cost (one NAT for both AZs). 2 matches the AT2 design (one NAT per AZ)."
  type        = number
  default     = 2

  validation {
    condition     = contains([1, 2], var.nat_gateway_count)
    error_message = "nat_gateway_count must be 1 or 2."
  }
}

variable "app_port" {
  description = "Port the ALB uses to reach the application instances. AT2 specifies HTTPS (443)."
  type        = number
  default     = 80
}
