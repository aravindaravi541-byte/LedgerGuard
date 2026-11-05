# LedgerGuard

A beginner-friendly multi-tenant billing dashboard built with Flask.

## Features
- Tenant login form
- Secure-style UI
- Basic billing calculation
- Simple dashboard for each tenant

## Run the app

```bash
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000/login
```

## Demo login

- Tenant ID: T001
- Email: admin@alphalabs.com
- Password: 123456

You can also try:

- Tenant ID: T002
- Email: finance@bluepeak.com
- Password: abcdef
