# Getting started: from this zip to a finished portfolio project

Follow the steps in order. Tick each one off. Commands are shown for macOS/Linux, with the Windows version where it differs. Do every AWS step in a **sandbox account**, never in a company or client account.

## Part 1: Set up your computer (about 30 minutes)

- [ ] Install **Python 3.10 or newer** (python.org). Check with `python --version`.
- [ ] Install **Git** (git-scm.com). Check with `git --version`.
- [ ] Install **VS Code** (code.visualstudio.com).
- [ ] Create a **GitHub account** if you do not have one.

## Part 2: Run the project locally (about 20 minutes)

1. Unzip `cloudwarden.zip` and open the `cloudwarden` folder in VS Code (File > Open Folder).
2. Open the terminal in VS Code (Terminal > New Terminal).
3. Create a virtual environment:
   - macOS/Linux: `python3 -m venv .venv && source .venv/bin/activate`
   - Windows PowerShell: `python -m venv .venv` then `.venv\Scripts\Activate.ps1`
   - If Windows blocks the script, run `Set-ExecutionPolicy -Scope Process Bypass` first, then try again.
4. Install everything: `pip install -e ".[azure,dev]"`
5. Run the tests: `pytest`. All tests should pass. If any fail, copy the full output and ask for help before going further.
6. Check the command works: `cloudwarden --help`

## Part 3: Put it on GitHub (about 15 minutes)

1. Check the name is free: search GitHub for `cloudwarden`, and open `pypi.org/project/cloudwarden` in your browser. If another well-known security tool already uses it, pick a different name (search and replace `cloudwarden` and `CloudWarden` in every file and rename the `cloudwarden/` package folder).
2. On GitHub, create a new empty repository named `cloudwarden`. Do not add a README or license there.
3. Open `README.md` and replace `<your-handle>` with your GitHub username.
4. In the terminal:
   ```
   git init
   git add .
   git commit -m "Initial CloudWarden v0.1"
   git branch -M main
   git remote add origin https://github.com/<your-handle>/cloudwarden.git
   git push -u origin main
   ```
5. Open the **Actions** tab on GitHub. The CI workflow should run the tests and turn green. If it fails, open the failed run and read the error.

## Part 4: Create a safe AWS sandbox (about 1 hour)

1. Create a new AWS account (free tier). Turn on **MFA** for the root user, then stop using root.
2. In Billing, create a **budget alert** (for example 5 USD).
3. In IAM, create a user `cloudwarden-scanner` and attach the AWS-managed policy **SecurityAudit** (read-only). Create an access key for it.
4. Install the AWS CLI (docs.aws.amazon.com/cli) and run `aws configure --profile cloudwarden`. Paste the key, set the region to `ap-south-1`.
5. Run your first scan on the empty account:
   `cloudwarden --aws --profile cloudwarden --region ap-south-1 --format html --output report.html`
6. Open `report.html` in your browser. A brand-new account usually shows few findings (often just "VPC has no flow logs" for the default VPC). That is expected.

## Part 5: Create the before-and-after evidence (about 2 hours)

This is the part that makes the project impressive.

1. Install **Terraform** (developer.hashicorp.com/terraform/install).
2. The scanner user is read-only, so Terraform needs a separate sandbox admin profile (create a second IAM user with permissions to create resources, only in the sandbox, with MFA). Configure it as `aws configure --profile sandbox-admin`.
3. Deploy the deliberately weak lab:
   ```
   cd lab
   terraform init
   terraform validate
   AWS_PROFILE=sandbox-admin terraform apply -var="bucket_name=cloudwarden-lab-<yourname>-123"
   ```
   (Windows PowerShell: set `$env:AWS_PROFILE="sandbox-admin"` first.) The bucket name must be globally unique.
4. Scan again and save it as **before**:
   `cloudwarden --aws --profile cloudwarden --region ap-south-1 --format html --output before.html`
   You should see the open security group, the unencrypted volume and the bucket without a public access block. Take a screenshot.
5. Fix the problems by editing `lab/main.tf`: change the SSH `cidr_blocks` to your own IP (for example `["203.0.113.5/32"]`), set `encrypted = true`, and set the four public access block values to `true`. Run `terraform apply` again.
6. Scan again and save it as **after**: `--output after.html`. Take a screenshot.
7. Remove everything: `terraform destroy`.
8. Create a `docs/screenshots/` folder, add your before and after screenshots, and show them in the README. Hide your AWS account ID in every screenshot.

## Part 6: Make the README yours (about 1 hour)

- [ ] Add the before and after screenshots and a screenshot of the HTML report.
- [ ] Fill in the **Results** table with real numbers.
- [ ] Write the **What I learned** section in your own words (4 to 5 honest bullets).
- [ ] Record a 3-minute screen video (Loom or similar): the problem, a scan, the report, a fix. Link it in the README.
- [ ] Add repository topics on GitHub: `aws`, `azure`, `cloud-security`, `python`, `security-tools`.
- [ ] Create a release: GitHub > Releases > Create a new release > tag `v0.1.0`.

## Part 7: Get real users (week 2)

1. Ask 3 to 5 people (classmates, a club, a small startup) who run AWS or Azure.
2. Get their **written permission** (a chat message saying yes is fine). Send them the read-only role instructions from `docs/SETUP.md`. Never ask for their access keys.
3. Run a scan, send each person their report, and help them fix the issues.
4. Keep a private table of: accounts scanned, findings, and how many were fixed. Remove names and account IDs before using any of it publicly.

## Part 8: Add it to your resume

Only after Parts 5 and 7, with your real numbers:

> **CloudWarden: Cloud Security Scanner** | Python, AWS, Azure, GitHub Actions | github.com/<your-handle>/cloudwarden
> Built an open-source tool that scans AWS and Azure for **[N] misconfiguration types**; used on **[N] real accounts**, finding **[N] issues** and helping fix **[N]**.

## If something goes wrong

- **A test fails or `pip install` errors:** copy the full error text and ask for help.
- **`AccessDenied` in a scan:** the report lists it under "Checks that could not run". Check that the SecurityAudit policy is attached to the scanner user.
- **No credentials found:** pass `--profile cloudwarden`, or run `aws configure list --profile cloudwarden` to check.
- **Terraform bucket name error:** the name is taken. Pick a more unique one.
