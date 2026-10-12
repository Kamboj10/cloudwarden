# Setup: read-only access for CloudWarden

CloudWarden only needs read access. Never give it write permissions, and never use root credentials.

## AWS

### Option A: local use

1. In IAM, create a user (or better, a role you assume) for scanning.
2. Attach the AWS-managed policy **SecurityAudit**. This is read-only and covers every call CloudWarden makes.
3. Configure credentials: `aws configure --profile cloudwarden`
4. Run: `cloudwarden --aws --profile cloudwarden --region ap-south-1`

Turn on MFA for the human user who can assume this access.

### Option B: GitHub Actions with OIDC (no stored keys)

1. In IAM, add an identity provider: type OpenID Connect, URL `https://token.actions.githubusercontent.com`, audience `sts.amazonaws.com`.
2. Create a role with the **SecurityAudit** policy and this trust policy. Replace the placeholders.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
        "StringLike": { "token.actions.githubusercontent.com:sub": "repo:YOUR_USER/cloudwarden:*" }
      }
    }
  ]
}
```

3. In your GitHub repository, add a secret named `AWS_ROLE_ARN` with the role's ARN.
4. The `sub` condition limits the role to your repository. Keep it as narrow as you can.

### Scanning someone else's account (a volunteer or small business)

- Get **written permission** first.
- Give them a role template (SecurityAudit plus a trust policy for your account) so they create it themselves. Never ask for access keys.
- Share the report only with them, and remove account IDs from anything you publish.

## Azure

1. Create a service principal with the Reader role on the subscription:

```bash
az ad sp create-for-rbac --name cloudwarden-reader --role Reader \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

2. The command prints `appId`, `password` and `tenant`. Export them:

```bash
export AZURE_CLIENT_ID=<appId>
export AZURE_CLIENT_SECRET=<password>
export AZURE_TENANT_ID=<tenant>
export AZURE_SUBSCRIPTION_ID=<subscription id>
```

3. Run: `cloudwarden --azure`

If you are already signed in with `az login`, CloudWarden picks that up automatically and you can skip step 2. Never commit these values to Git. Keep them in a `.env` file that is listed in `.gitignore`.

## Costs

All the API calls CloudWarden makes are free or negligible. Create a billing alert in each account anyway.
