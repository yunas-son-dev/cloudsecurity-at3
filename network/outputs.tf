output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "ALB subnets (one per AZ)."
  value       = aws_subnet.public[*].id
}

output "app_subnet_ids" {
  description = "Application subnets: Elastic Beanstalk instances go here."
  value       = aws_subnet.app[*].id
}

output "db_subnet_ids" {
  value = aws_subnet.db[*].id
}

output "db_subnet_group_name" {
  description = "Pick this subnet group when creating RDS."
  value       = aws_db_subnet_group.main.name
}

output "sg_alb_id" {
  value = aws_security_group.alb.id
}

output "sg_app_id" {
  value = aws_security_group.app.id
}

output "sg_db_id" {
  value = aws_security_group.db.id
}

output "secretsmanager_endpoint_id" {
  value = aws_vpc_endpoint.secretsmanager.id
}

output "s3_endpoint_id" {
  value = aws_vpc_endpoint.s3.id
}

output "nat_gateway_ids" {
  value = aws_nat_gateway.main[*].id
}

# Copy this block into the team chat. It contains no secrets.
output "team_summary" {
  value = <<-EOT
    Namawin network is ready (region ${var.region}).
    VPC:             ${aws_vpc.main.id} (${var.vpc_cidr})
    Public subnets:  ${join(", ", aws_subnet.public[*].id)}   (ALB)
    App subnets:     ${join(", ", aws_subnet.app[*].id)}   (Elastic Beanstalk instances)
    DB subnets:      ${join(", ", aws_subnet.db[*].id)}   (RDS)
    DB subnet group: ${aws_db_subnet_group.main.name}
    SG-ALB:          ${aws_security_group.alb.id}
    SG-APP:          ${aws_security_group.app.id}
    SG-DB:           ${aws_security_group.db.id}
  EOT
}
