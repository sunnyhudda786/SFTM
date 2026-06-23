<!-- Using a web link -->
![Company Logo]([https://example.com](https://github.com/sunnyhudda786/SFTM/blob/main/sftm_logo.png))


# Secure File Transfer Monitoring System

Clean Django + SQLite project for file-transfer monitoring, alert ownership, OTP password reset, and escalation email alerts.

This zip does **not** include any database, users, or policies. Create your superuser first, then create users and a policy from the web UI.

## Fresh setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open:

```text
http://127.0.0.1:8000/
```

## Email setup

Edit `.env` beside `manage.py`.

```env
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=true
EMAIL_HOST_USER=shudda7860@gmail.com
EMAIL_HOST_PASSWORD=your_new_gmail_app_password
DEFAULT_FROM_EMAIL=Secure File Transfer Monitor <shudda7860@gmail.com>
OTP_EXPIRY_MINUTES=10
SFTM_OWNER_EMAIL=sunnycanadaedu@gmail.com
SFTM_FIRST_ADMIN_EMAIL=nehalcanadaedu@gmail.com
```

Restart the server after editing `.env`.

## Manual setup in the website

1. Login as the superuser.
2. Go to **Users/Roles**.
3. Create one Admin, one or two Analysts, and one Auditor.
4. Go to **Policies**.
5. Create one policy and assign those users to it.
6. Add monitored folder paths, sensitive folder paths, allowed destinations, and escalation recipients.

You can use these built-in folders for testing:

```text
workspace/Corporate
workspace/Corporate/Sensitive
workspace/Corporate/Approved
workspace/Corporate/USB_Drive
workspace/Corporate/CloudSync
workspace/Corporate/NetworkShare
```

## Start monitoring

Use separate terminals.

Website:

```bash
source .venv/bin/activate
python manage.py runserver
```

File monitor:

```bash
source .venv/bin/activate
python manage.py runmonitor
```

Escalation worker:

```bash
source .venv/bin/activate
python manage.py run_escalation_worker --interval 30
```

Integrity scan:

```bash
source .venv/bin/activate
python manage.py scan_integrity
```

## Test an alert

Create a file in the sensitive folder and copy it to USB_Drive while `runmonitor` is running:

```bash
echo "salary test data" > workspace/Corporate/Sensitive/salary.xlsx
cp workspace/Corporate/Sensitive/salary.xlsx workspace/Corporate/USB_Drive/salary.xlsx
```

Refresh **Dashboard → Alerts**.

## Alert categorization and email templates

The project categorizes alerts by combining policy-based sensitivity rules and risk scoring.

### Sensitivity classification

A file can be marked sensitive when it matches one or more policy rules:

- Sensitive directory: the file is inside a configured sensitive folder.
- Restricted filename: the filename exactly matches a restricted file such as `salary.xlsx` or `client_data.csv`.
- Sensitive keyword: the filename contains words such as `salary`, `client`, `confidential`, `database`, or `password`.
- Sensitive extension: the extension matches configured sensitive types such as `.xlsx`, `.csv`, `.pdf`, `.sql`, `.zip`, `.pem`, or `.key`.

### Risk scoring and severity

The security engine adds risk points when a sensitive file appears outside an approved destination, matches a blocked USB/cloud/network keyword, shows bulk-transfer behavior, or shows integrity/hash mismatch evidence.

Severity bands:

- Critical: 90-100 risk score
- High: 65-89 risk score
- Medium: 35-64 risk score
- Low: 10-34 risk score
- Info: 0-9 risk score

### Email templates

The project uses HTML email templates for:

- OTP password reset: `monitor/templates/monitor/emails/otp_email.html`
- New alert and unclaimed alert escalation: `monitor/templates/monitor/emails/alert_email.html`

The alert email includes severity, risk score, category, matched policy rules, file path evidence, hash evidence, owner status, escalation reason, and recommended response steps.

To show a logo in emails, add a public HTTPS logo URL in `.env`:

```env
PROJECT_LOGO_URL=https://raw.githubusercontent.com/YOUR_USERNAME/sftm-public-assets/main/sftm_logo.png
SFTM_DASHBOARD_URL=http://127.0.0.1:8000
```

The system still works if `PROJECT_LOGO_URL` is blank; the emails will simply show without the logo image.
