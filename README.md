# Namawin sample app (42035 Cloud Security, Assessment Task 3)

Namawin is a **fictional** Australian digital bank. This small Flask app is the
target for the security controls designed in our earlier report. It is not
meant to look polished. It is meant to be easy to read and to demonstrate:

| Control | Where in the code |
|---|---|
| Cognito sign-in with TOTP MFA | `app/auth.py` (login + `/login/mfa`) |
| JWT validation on every request | `app/auth.py` (`validate_token`, `@require_auth`) |
| AWS WAF SQL injection protection (plus safe parameterised SQL) | `app/search.py` |
| KMS-encrypted S3 uploads (SSE-KMS) | `app/documents.py` |
| KMS-encrypted RDS over required TLS | `app/db.py` |
| Secrets Manager for DB credentials and the Flask key | `app/secrets.py` |
| Rule-based transaction checks | `app/transactions.py` (`evaluate_transaction`) |
| Security headers, CSRF token, secure cookies, ProxyFix | `app/__init__.py` |
| Structured security logging (JSON to CloudWatch) | `app/logging_setup.py` |

**Ownership:** Fathima owns identity (`auth.py`). Ashwin owns data and application
security (`secrets.py`, `db.py`, `transactions.py`, `documents.py`, `search.py`).
Search for `OWNER:` and `EXTENSION POINT:` comments.

## Keeping secrets out of Git

`.gitignore` excludes `.env` files, keys, AWS credential files and all Terraform
state (`*.tfstate`, `.terraform/`, `*.tfvars`). A pre-commit hook also blocks those
files and AWS-key / private-key / password patterns. **Run this once after cloning:**

```bash
git config core.hooksPath .githooks
```

The built bundle `dist/namawin-app.zip` is committed so the team can deploy it
without building. Rebuild it with `./build.sh` whenever the app changes.

## Pages

| Path | Auth | Purpose |
|---|---|---|
| `GET /health` | public | Returns `ok` (ALB health check). Does not touch the DB. |
| `GET/POST /login`, `/login/mfa`, `GET /logout` | public | Cognito sign-in, then the 6-digit TOTP step |
| `GET/POST /transactions` | login | Make a payment and see status and the rule triggered |
| `GET/POST /documents` | login | Upload to S3 (SSE-KMS) and list files with encryption status |
| `GET /search?q=...` | public | Help-article search, the WAF SQLi demo target |

## Run locally (no AWS needed)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env          # optional; the defaults already work
flask --app application run
```

Open http://127.0.0.1:5000. Local mode uses a SQLite file (`namawin-local.sqlite`),
saves uploads to `./local_uploads/`, and with `AUTH_REQUIRED=false` every
request acts as `demo-user`. A loud warning is logged at startup.

Run the tests:

```bash
pytest
```

## Environment variables

Set these as **Elastic Beanstalk environment properties** (Configuration →
Updates, monitoring and logging → Environment properties). Never commit real values.

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `local`, or `aws` if any of `DB_SECRET_NAME`/`S3_BUCKET`/`COGNITO_USER_POOL_ID` is set | `local` = SQLite + local disk. `aws` = RDS + S3 + Secrets Manager. |
| `SECRET_KEY` | random per process in local mode | Flask session-signing key. In AWS prefer `APP_SECRET_NAME`. |
| `APP_SECRET_NAME` | – | Secrets Manager secret holding the Flask key (plain text or `{"SECRET_KEY": "..."}`). Takes priority over `SECRET_KEY`. |
| `AWS_REGION` | `ap-southeast-2` | Region for all AWS calls. |
| `DB_SECRET_NAME` | – | **Required in aws mode.** Secrets Manager secret with the RDS credentials (`username`, `password`, `host`, `port`, `dbname`). |
| `RDS_CA_BUNDLE` | – | **Required in aws mode.** Path to the RDS CA bundle, e.g. `/etc/pki/rds/global-bundle.pem`. |
| `S3_BUCKET` | – | Bucket for uploaded documents (aws mode). |
| `KMS_KEY_ID` | – | KMS key ID or ARN used for `SSEKMSKeyId` on uploads. |
| `COGNITO_USER_POOL_ID` | – | e.g. `ap-southeast-2_XXXXXXXXX`. Required when `AUTH_REQUIRED=true`. |
| `COGNITO_APP_CLIENT_ID` | – | App client **without a client secret** that allows `USER_PASSWORD_AUTH`. |
| `AUTH_REQUIRED` | `true` in aws mode, `false` in local mode | `false` disables authentication (demo user). Only for local dev or the first deployment before Cognito exists. |
| `TXN_AMOUNT_LIMIT` | `5000` | Amounts **above** this are held (`AMOUNT_OVER_LIMIT`). |
| `TXN_MAX_PER_WINDOW` | `5` | If the user already has this many transactions in the window, the next one is held (`FREQUENCY_EXCEEDED`). |
| `TXN_WINDOW_MINUTES` | `10` | Length of the frequency window. |

The app refuses to start, with a clear error, if a required setting is missing.

## Deploy to Elastic Beanstalk

### 1. Prerequisites (from the report's design)

- **RDS for MySQL**: storage encrypted with KMS, in private subnets, initial database
  name `namawin`. Set the parameter group value `require_secure_transport = 1` so
  the server also refuses non-TLS connections.
- **Secrets Manager**: a secret of type "Credentials for Amazon RDS database" for
  that instance, containing `username`, `password`, `host`, `port` and `dbname`.
  (If you use the RDS-managed master secret, which only holds username and
  password, add `host` and `dbname` to a separate secret instead.)
- Optionally a second secret for the Flask key, e.g. `{"SECRET_KEY": "<64 random hex chars>"}`.
- **S3 bucket**: Block Public Access on, default encryption SSE-KMS with your key,
  and versioning on.
- **KMS customer-managed key**: its key policy must allow the instance role to use it.
- **Cognito user pool** with MFA set to *required* (TOTP), and an app client
  without a secret with `ALLOW_USER_PASSWORD_AUTH` enabled.

### 2. Instance profile permissions

Attach a policy like this to the EB EC2 instance role (for example
`aws-elasticbeanstalk-ec2-role`). Replace the placeholders with your ARNs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
      "Resource": ["<db-secret-arn>", "<app-secret-arn>"] },
    { "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
      "Resource": "arn:aws:s3:::<bucket>/*" },
    { "Effect": "Allow", "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::<bucket>" },
    { "Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
      "Resource": "<kms-key-arn>" }
  ]
}
```

`head_object` is covered by `s3:GetObject`. The Cognito sign-in APIs used here
(`InitiateAuth`, `RespondToAuthChallenge`) are public and need no IAM permission.

### 3. RDS CA bundle

The app verifies the RDS TLS certificate against the AWS RDS global CA bundle:
https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
(documented at https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html).

The deployment hook `.platform/hooks/prebuild/01_rds_ca_bundle.sh` downloads it
to `/etc/pki/rds/global-bundle.pem` on every deploy, so set
`RDS_CA_BUNDLE=/etc/pki/rds/global-bundle.pem`. The instances need outbound HTTPS,
for example through a NAT gateway.

### 4. Build and upload

```bash
./build.sh
```

This creates `dist/namawin-app.zip` with the files at the root of the zip.

In the EB console:

1. **Create environment** → Web server environment → Platform **Python** (Amazon Linux 2023).
2. Application code → **Upload your code** → choose `dist/namawin-app.zip`.
3. Service access → choose the EC2 instance profile from step 2.
4. Networking → your VPC, instances in private subnets, load balancer in public subnets.
5. Instance traffic and scaling → **Load balanced**, **Application Load Balancer**.
   Add an **HTTPS :443 listener** with your ACM certificate, and redirect or remove port 80.
   Set the default process **health check path** to `/health`.
6. Updates, monitoring and logging → **Environment properties** → add the variables
   above. Turn on CloudWatch log streaming so the JSON logs are kept.
7. Create the environment. Then attach your **AWS WAF web ACL** to the environment's
   ALB (WAF console → Web ACLs → Associated AWS resources).

For later versions, run `./build.sh` again and use **Upload and deploy** on the environment.

First deployment before Cognito exists: set `AUTH_REQUIRED=false`, check
`/health` and `/search`, then add the Cognito variables, set `AUTH_REQUIRED=true`
and redeploy.

## Demo ideas

Replace `https://<your-env-url>` with the HTTPS address of the environment.

**Health:**
```bash
curl -i https://<your-env-url>/health
```

**Search: normal request vs SQL injection blocked by WAF.**
```bash
curl -i "https://<your-env-url>/search?q=MFA"
curl -i "https://<your-env-url>/search?q=%27%20OR%20%271%27%3D%271"
```
The first returns 200 with the "How to set up MFA" article. The second, `' OR '1'='1`,
should get **403 from AWS WAF** (managed rule group `AWSManagedRulesSQLiRuleSet`).
Show the matching entry in the WAF logs or the sampled requests. Then run the same
payload locally with no WAF: you get 200 and "No results.", which shows the app's
parameterised query is safe on its own (defence in depth).
`tests/test_search.py` proves the same.

**Held transaction:**
- Sign in, then pay `5000.01`. It shows `HELD_FOR_REVIEW / AMOUNT_OVER_LIMIT`.
- Make 6 small payments within 10 minutes. The 6th shows `FREQUENCY_EXCEEDED`.
- In CloudWatch Logs Insights:
  `fields @timestamp, user_id, rule | filter event = "transaction_held"`.

**S3 object encrypted with KMS:** upload a PDF on `/documents`. The table shows
`aws:kms` and the key ARN, read live with `head_object`. Confirm from the CLI:
```bash
aws s3api head-object --bucket <bucket> --key "<user-sub>/<uuid>-file.pdf"
```
Look for `"ServerSideEncryption": "aws:kms"` and `"SSEKMSKeyId"`.

**Invalid token rejected:**
```bash
curl -i -H "Accept: application/json" https://<your-env-url>/transactions
curl -i -H "Authorization: Bearer not-a-real-token" https://<your-env-url>/transactions
curl -i -H "Authorization: Bearer <access token with one character changed>" https://<your-env-url>/transactions
```
Each returns **401** with a JSON reason (`missing token`, `malformed token`,
`invalid token: Signature verification failed`), and a `token_rejected` event is
logged. A valid access token (for example from
`aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH ...`) returns 200.
`tests/test_auth.py` also covers expired tokens, the wrong issuer, the wrong app
client and `alg: none`.

## Security notes and trade-offs

- **Tokens live in the session cookie.** The cookie is signed (tamper-proof), `HttpOnly`,
  `Secure` (aws mode) and `SameSite=Lax`, but it is not encrypted. The user's own
  access token is readable by them, which is fine. Only the access token is stored,
  not the refresh token, so sessions end after at most 1 hour.
- **CSRF:** HTML form POSTs need a per-session token. Bearer-token requests skip
  the check because browsers cannot forge that header cross-site.
- **ProxyFix** trusts `X-Forwarded-For` 2 hops deep (ALB + nginx on the instance) and
  `X-Forwarded-Proto`/`Port` 1 hop deep. This is only correct while instances accept
  traffic **only from the ALB** (security group rule).
- **Login failures log the email entered**, so brute-force attempts can be spotted.
  Passwords, MFA codes, tokens and secrets are never logged.
- The search page logs the query **length**, not the raw text.

## Known limitations

- Demo only: no real money movement, no account balances, no review queue for held
  transactions, and no download endpoint for documents.
- The frequency check is not atomic. Two simultaneous requests could both pass when
  the user is at the limit (a production version would lock the row or use a counter).
- Cognito `MFA_SETUP` (first-time TOTP enrolment) and `NEW_PASSWORD_REQUIRED` are
  not handled in the app. Enrol users through the Cognito console or CLI first.
- Logout only clears the browser session. It does not call Cognito `GlobalSignOut`,
  so a stolen access token stays valid until it expires (at most 1 hour).
- After a wrong MFA code the user restarts from the password step.
- Schema creation runs at startup (`create_all`). That is fine for one instance, but
  real deployments should use migrations (e.g. Alembic).
- Uploads are checked by extension and size only. There is no content sniffing or
  malware scanning.
- SQLite in local mode stores amounts without exact decimal support. RDS MySQL uses
  `DECIMAL(12,2)`.
- Secrets are read once at startup. After a secret rotation the app needs a restart.
- The RDS CA download hook needs outbound internet from the instances.
