from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)
app.secret_key = "ledgerguard-demo-secret-key"

TENANTS = {
    "T001": {
        "tenant_id": "T001",
        "name": "Alpha Labs",
        "email": "admin@alphalabs.com",
        "password": "123456",
        "plan": "Starter",
        "usage": 120,
        "rate": 2.5,
        "currency": "USD",
        "status": "Active"
    },
    "T002": {
        "tenant_id": "T002",
        "name": "Bluepeak Inc",
        "email": "finance@bluepeak.com",
        "password": "abcdef",
        "plan": "Pro",
        "usage": 360,
        "rate": 3.0,
        "currency": "USD",
        "status": "Active"
    }
}


def calculate_bill(usage, rate):
    return round(usage * rate, 2)


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        tenant_id = request.form.get("tenant_id", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        tenant = TENANTS.get(tenant_id)

        if tenant and tenant["email"] == email and tenant["password"] == password:
            bill = calculate_bill(tenant["usage"], tenant["rate"])
            return render_template(
                "dashboard.html",
                tenant=tenant,
                bill=bill,
                usage=tenant["usage"],
                rate=tenant["rate"],
                currency=tenant["currency"],
            )

        error = "Invalid tenant ID, email, or password."

    return render_template("login.html", error=error)


if __name__ == "__main__":
    app.run(debug=True)
