################################################################################
# Namawin network layer (AT2 section 7.1 and Figure 3)
# Owner: Yuna. Deploy first, then share the outputs with Ashwin and Fathima.
################################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  # Maps keyed by index so rule numbers stay stable.
  public_cidr_map = { for i, c in var.public_subnet_cidrs : tostring(i) => c }
  app_cidr_map    = { for i, c in var.app_subnet_cidrs : tostring(i) => c }
  db_cidr_map     = { for i, c in var.db_subnet_cidrs : tostring(i) => c }
}

# ------------------------------------------------------------------------------
# VPC, subnets, gateways
# ------------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-public-${count.index + 1}", tier = "public" }
}

resource "aws_subnet" "app" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.app_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-app-${count.index + 1}", tier = "app" }
}

resource "aws_subnet" "db" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.db_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-db-${count.index + 1}", tier = "db" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-igw" }
}

resource "aws_eip" "nat" {
  count  = var.nat_gateway_count
  domain = "vpc"

  tags = { Name = "${var.name_prefix}-nat-eip-${count.index + 1}" }
}

resource "aws_nat_gateway" "main" {
  count         = var.nat_gateway_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = { Name = "${var.name_prefix}-nat-${count.index + 1}" }

  depends_on = [aws_internet_gateway.main]
}

# ------------------------------------------------------------------------------
# Route tables
# ------------------------------------------------------------------------------

# Public: internet gateway.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.name_prefix}-rt-public" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# App: outbound internet through NAT (platform updates). One route table per AZ.
resource "aws_route_table" "app" {
  count  = 2
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index % var.nat_gateway_count].id
  }

  tags = { Name = "${var.name_prefix}-rt-app-${count.index + 1}" }
}

resource "aws_route_table_association" "app" {
  count          = 2
  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app[count.index].id
}

# DB: local routes only. No internet route at all (AT2 section 7.1).
resource "aws_route_table" "db" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-rt-db" }
}

resource "aws_route_table_association" "db" {
  count          = 2
  subnet_id      = aws_subnet.db[count.index].id
  route_table_id = aws_route_table.db.id
}

# ------------------------------------------------------------------------------
# VPC endpoints
# ------------------------------------------------------------------------------

# S3 gateway endpoint on the app route tables.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.app[*].id

  tags = { Name = "${var.name_prefix}-vpce-s3" }
}

# Secrets Manager interface endpoint, reachable only from SG-APP.
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.app[*].id
  security_group_ids  = [aws_security_group.endpoint.id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-vpce-secretsmanager" }
}

# ------------------------------------------------------------------------------
# Security groups (stateful). Rules are separate resources to avoid circular refs.
# ------------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-sg-alb"
  description = "ALB: HTTPS from the internet"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-sg-alb" }
}

resource "aws_security_group" "app" {
  name        = "${var.name_prefix}-sg-app"
  description = "Application instances: traffic from the ALB only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-sg-app" }
}

resource "aws_security_group" "db" {
  name        = "${var.name_prefix}-sg-db"
  description = "RDS MySQL: traffic from the application tier only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-sg-db" }
}

resource "aws_security_group" "endpoint" {
  name        = "${var.name_prefix}-sg-vpce"
  description = "Secrets Manager interface endpoint: HTTPS from SG-APP only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-sg-vpce" }
}

# SG-ALB: 443 in from the internet, app port out to SG-APP.
resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from the internet"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To application instances"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
}

# SG-APP: app port in from SG-ALB. Out to RDS, HTTPS out (NAT, S3 endpoint, Secrets Manager endpoint).
resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "From the ALB"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id            = aws_security_group.app.id
  description                  = "MySQL to RDS"
  referenced_security_group_id = aws_security_group.db.id
  ip_protocol                  = "tcp"
  from_port                    = 3306
  to_port                      = 3306
}

resource "aws_vpc_security_group_egress_rule" "app_https_out" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to NAT, S3 and Secrets Manager endpoints"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# SG-DB: 3306 in from SG-APP only. No egress rules.
resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "MySQL from the application tier"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 3306
  to_port                      = 3306
}

# SG-VPCE: 443 in from SG-APP only.
resource "aws_vpc_security_group_ingress_rule" "endpoint_from_app" {
  security_group_id            = aws_security_group.endpoint.id
  description                  = "HTTPS from the application tier"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# ------------------------------------------------------------------------------
# Network ACLs (stateless): allow requests and the return ports (AT2 section 7.1)
# ------------------------------------------------------------------------------

resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id

  # HTTPS from clients, return traffic from the internet and the app tier.
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }
  # ALB to the app tier on app_port (needed when app_port is not 443)
  dynamic "egress" {
    for_each = local.app_cidr_map
    content {
      rule_no    = 105 + tonumber(egress.key)
      protocol   = "tcp"
      action     = "allow"
      cidr_block = egress.value
      from_port  = var.app_port
      to_port    = var.app_port
    }
  }
  # HTTPS to the app tier and out through NAT, replies to clients.
  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }
  egress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  tags = { Name = "${var.name_prefix}-nacl-public" }
}

resource "aws_network_acl" "app" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.app[*].id

  # App port from the ALB subnets.
  dynamic "ingress" {
    for_each = local.public_cidr_map
    content {
      rule_no    = 100 + tonumber(ingress.key)
      protocol   = "tcp"
      action     = "allow"
      cidr_block = ingress.value
      from_port  = var.app_port
      to_port    = var.app_port
    }
  }
  # HTTPS between app subnets (cross-AZ access to the Secrets Manager endpoint).
  dynamic "ingress" {
    for_each = local.app_cidr_map
    content {
      rule_no    = 110 + tonumber(ingress.key)
      protocol   = "tcp"
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 443
      to_port    = 443
    }
  }
  # Return traffic from NAT, S3, the DB tier and endpoints.
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # HTTPS out (NAT, S3, Secrets Manager endpoint).
  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }
  # MySQL to the DB subnets only.
  dynamic "egress" {
    for_each = local.db_cidr_map
    content {
      rule_no    = 110 + tonumber(egress.key)
      protocol   = "tcp"
      action     = "allow"
      cidr_block = egress.value
      from_port  = 3306
      to_port    = 3306
    }
  }
  # Replies to the ALB.
  dynamic "egress" {
    for_each = local.public_cidr_map
    content {
      rule_no    = 200 + tonumber(egress.key)
      protocol   = "tcp"
      action     = "allow"
      cidr_block = egress.value
      from_port  = 1024
      to_port    = 65535
    }
  }

  tags = { Name = "${var.name_prefix}-nacl-app" }
}

resource "aws_network_acl" "db" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.db[*].id

  # MySQL from the app subnets only.
  dynamic "ingress" {
    for_each = local.app_cidr_map
    content {
      rule_no    = 100 + tonumber(ingress.key)
      protocol   = "tcp"
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 3306
      to_port    = 3306
    }
  }

  # Replies to the app subnets only.
  dynamic "egress" {
    for_each = local.app_cidr_map
    content {
      rule_no    = 100 + tonumber(egress.key)
      protocol   = "tcp"
      action     = "allow"
      cidr_block = egress.value
      from_port  = 1024
      to_port    = 65535
    }
  }

  tags = { Name = "${var.name_prefix}-nacl-db" }
}

# ------------------------------------------------------------------------------
# RDS subnet group (Ashwin selects this when creating the database)
# ------------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db-subnets"
  subnet_ids = aws_subnet.db[*].id

  tags = { Name = "${var.name_prefix}-db-subnets" }
}
