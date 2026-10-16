# network/ (Terraform)

Namawin VPC from the AT2 report (section 7.1, Figure 3). Owner: Yuna.

## What it creates
- VPC `10.20.0.0/16` in ap-southeast-2, two AZs
- 2 public, 2 private app, 2 private DB subnets
- Internet gateway, one NAT gateway per AZ, S3 gateway endpoint, Secrets Manager interface endpoint
- Route tables (DB tier has no internet route)
- Security groups: SG-ALB, SG-APP, SG-DB, plus SG-VPCE for the Secrets Manager endpoint
- Network ACLs for each tier (stateless: request and return ports)
- RDS subnet group `namawin-db-subnets`

## Use
```
aws sts get-caller-identity      # confirm the account and user before applying
terraform init
terraform plan
terraform apply
terraform output team_summary    # paste into the team chat
```

Destroy after recording to stop NAT charges: `terraform destroy`.

## Deviations from the AT2 design (write these in the reflection)
- `app_port = 80` between the ALB and the app instances (design says 443). Elastic Beanstalk instances listen on 80 behind nginx. Clients still reach the ALB over HTTPS on 443.
- SG-VPCE is a dedicated group so the endpoint accepts HTTPS from SG-APP only.

## Notes
- The ALB reaches the app on `app_port` (80 by default). Set it to 443 only after configuring HTTPS on the instances.- Keep `*.tfstate` out of Git (see `.gitignore`). Never commit access keys.
