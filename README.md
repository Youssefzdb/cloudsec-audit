# cloudsec-audit ☁️

Cloud Infrastructure Security Auditing Framework

## Features
- AWS S3 public bucket detection
- Security group open port audit
- Cloud config misconfiguration checks
- IAM overprivilege & stale key detection
- JSON report export

## Usage
```bash
pip install -r requirements.txt

# AWS live audit (requires configured AWS credentials)
python main.py --provider aws --output aws_report.json

# Config file audit
python main.py --config cloud_config.json --output report.json
```

## Sample Config
```json
{
  "logging": {"enabled": true},
  "mfa": {"required": true},
  "encryption": {"at_rest": true, "in_transit": true},
  "iam": {"users": [{"name": "admin", "policies": ["AdministratorAccess"], "mfa_enabled": false}]}
}
```
