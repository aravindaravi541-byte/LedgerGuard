import streamlit as st
import pandas as pd
from datetime import date, datetime

# =====================================================
# 1. PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="LedgerGuard - Secure Billing",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =====================================================
# 2. CUSTOM CSS
# =====================================================

st.markdown("""
<style>
.stApp {
    background-color: #f5f6fb;
}

[data-testid="stSidebar"] {
    background-color: #10172a;
}

[data-testid="stSidebar"] * {
    color: white;
}

.login-box {
    background-color: white;
    padding: 35px;
    border-radius: 15px;
    border: 1px solid #e5e7ef;
    box-shadow: 0 10px 35px rgba(0,0,0,0.12);
}

.login-logo {
    text-align: center;
    font-size: 48px;
}

.login-title {
    text-align: center;
    font-size: 30px;
    font-weight: bold;
    color: #242944;
}

.login-subtitle {
    text-align: center;
    color: #858b9d;
    margin-bottom: 25px;
}

.metric-card {
    background: white;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #e5e7ef;
}

.metric-label {
    color: #858b9d;
    font-size: 13px;
}

.metric-value {
    color: #252a40;
    font-size: 25px;
    font-weight: bold;
}

div.stButton > button {
    background-color: #5c55ca;
    color: white;
    border-radius: 7px;
    border: none;
}

div.stButton > button:hover {
    background-color: #4540a8;
    color: white;
}
</style>
""", unsafe_allow_html=True)


# =====================================================
# 3. INITIALIZE SESSION DATA
# =====================================================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "user_email" not in st.session_state:
    st.session_state.user_email = ""

if "invoices" not in st.session_state:
    st.session_state.invoices = [
        {
            "Invoice ID": "INV-1001",
            "Company": "Northstar Logistics",
            "Date": date.today(),
            "Amount": 48500,
            "Status": "Paid"
        },
        {
            "Invoice ID": "INV-1002",
            "Company": "Aster Healthcare",
            "Date": date.today(),
            "Amount": 32000,
            "Status": "Pending"
        },
        {
            "Invoice ID": "INV-1003",
            "Company": "Bluepeak Retail",
            "Date": date.today(),
            "Amount": 76250,
            "Status": "Paid"
        },
        {
            "Invoice ID": "INV-1004",
            "Company": "Crestline Labs",
            "Date": date.today(),
            "Amount": 18900,
            "Status": "Overdue"
        }
    ]

if "tenants" not in st.session_state:
    st.session_state.tenants = [
        {
            "Tenant ID": "TEN-001",
            "Company": "Northstar Logistics",
            "Plan": "Enterprise",
            "Users": 24,
            "Status": "Active"
        },
        {
            "Tenant ID": "TEN-002",
            "Company": "Aster Healthcare",
            "Plan": "Growth",
            "Users": 12,
            "Status": "Active"
        },
        {
            "Tenant ID": "TEN-003",
            "Company": "Bluepeak Retail",
            "Plan": "Business",
            "Users": 18,
            "Status": "Active"
        },
        {
            "Tenant ID": "TEN-004",
            "Company": "Crestline Labs",
            "Plan": "Starter",
            "Users": 6,
            "Status": "Review"
        }
    ]

if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = [
        {
            "Event": "Invoice Generated",
            "Company": "Northstar Logistics",
            "Action": "CREATE",
            "Date": str(date.today()),
            "Status": "Recorded"
        },
        {
            "Event": "Payment Received",
            "Company": "Aster Healthcare",
            "Action": "PAYMENT",
            "Date": str(date.today()),
            "Status": "Recorded"
        }
    ]


# =====================================================
# 4. LOGIN PAGE
# =====================================================

if not st.session_state.logged_in:

    st.markdown("<br><br>", unsafe_allow_html=True)

    left, center, right = st.columns([1, 1.2, 1])

    with center:

        st.markdown('<div class="login-box">', unsafe_allow_html=True)

        st.markdown(
            '<div class="login-logo">🛡️</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            '<div class="login-title">LedgerGuard</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            '<div class="login-subtitle">'
            'Dynamic Multi-Tenant Zero-Knowledge Billing Engine'
            '</div>',
            unsafe_allow_html=True
        )

        st.subheader("Welcome Back")
        st.write("Sign in to access your secure billing dashboard.")

        with st.form("login_form"):

            email = st.text_input(
                "Email Address",
                placeholder="admin@ledgerguard.com"
            )

            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter your password"
            )

            remember = st.checkbox("Remember me")

            login_button = st.form_submit_button(
                "Sign In",
                use_container_width=True
            )

            if login_button:

                if (
                    email == "admin@ledgerguard.com"
                    and password == "Admin@123"
                ):

                    st.session_state.logged_in = True
                    st.session_state.user_email = email

                    st.success("Login successful!")
                    st.rerun()

                else:
                    st.error("Invalid email or password.")

        st.markdown(
            "<center><small>🛡️ Protected by LedgerGuard Security</small></center>",
            unsafe_allow_html=True
        )

        st.markdown('</div>', unsafe_allow_html=True)

    st.stop()


# =====================================================
# 5. SIDEBAR NAVIGATION
# =====================================================

st.sidebar.markdown("# 🛡️ LedgerGuard")
st.sidebar.caption("SECURE BILLING ENGINE")

st.sidebar.divider()

st.sidebar.markdown("### 🏢 Acme Corporation")
st.sidebar.caption("Enterprise Workspace")

page = st.sidebar.radio(
    "MAIN MENU",
    [
        "Dashboard",
        "Invoices",
        "Tenants",
        "Ledger Audit",
        "Security",
        "Settings"
    ]
)

st.sidebar.divider()

st.sidebar.write("👤 Admin User")
st.sidebar.caption(st.session_state.user_email)

if st.sidebar.button("🚪 Logout", use_container_width=True):

    st.session_state.logged_in = False
    st.session_state.user_email = ""

    st.rerun()


# =====================================================
# 6. DASHBOARD PAGE
# =====================================================

if page == "Dashboard":

    st.title("Welcome to LedgerGuard 👋")

    st.caption(
        "Manage your billing operations securely."
    )

    st.success(
        "🛡️ Security Status: Workspace monitoring is active."
    )

    invoice_df = pd.DataFrame(
        st.session_state.invoices
    )

    total_revenue = invoice_df[
        invoice_df["Status"] == "Paid"
    ]["Amount"].sum()

    total_invoices = len(invoice_df)

    active_tenants = sum(
        1 for tenant in st.session_state.tenants
        if tenant["Status"] == "Active"
    )

    outstanding = invoice_df[
        invoice_df["Status"].isin(["Pending", "Overdue"])
    ]["Amount"].sum()

    # METRICS

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "💰 Total Revenue",
        f"₹{total_revenue:,.0f}"
    )

    col2.metric(
        "📄 Total Invoices",
        total_invoices
    )

    col3.metric(
        "🏢 Active Tenants",
        active_tenants
    )

    col4.metric(
        "⏳ Outstanding Amount",
        f"₹{outstanding:,.0f}"
    )

    st.divider()

    # REVENUE CHART

    left, right = st.columns(2)

    with left:

        st.subheader("📊 Revenue Overview")

        revenue_data = pd.DataFrame({
            "Month": [
                "June", "July", "August",
                "September", "October", "November"
            ],
            "Revenue": [
                45000, 62000, 58000,
                85000, 92000, 105000
            ]
        })

        st.bar_chart(
            revenue_data.set_index("Month")
        )

    with right:

        st.subheader("📈 Invoice Status")

        status_data = invoice_df[
            "Status"
        ].value_counts()

        st.bar_chart(status_data)

    st.divider()

    # RECENT INVOICES

    st.subheader("📋 Recent Invoices")

    st.dataframe(
        invoice_df,
        use_container_width=True,
        hide_index=True
    )

    # PLATFORM HEALTH

    st.subheader("⚙️ Platform Health")

    h1, h2, h3 = st.columns(3)

    h1.success("API Gateway: Demo status")
    h2.success("Tenant Isolation: Demo status")
    h3.success("Ledger Monitoring: Demo status")


# =====================================================
# 7. INVOICE MANAGEMENT
# =====================================================

elif page == "Invoices":

    st.title("📄 Invoice Management")

    st.caption(
        "Create and manage company invoices."
    )

    with st.expander("➕ Create New Invoice"):

        with st.form("invoice_form"):

            company_names = [
                tenant["Company"]
                for tenant in st.session_state.tenants
            ]

            company = st.selectbox(
                "Select Company",
                company_names
            )

            amount = st.number_input(
                "Invoice Amount (₹)",
                min_value=1,
                step=100
            )

            status = st.selectbox(
                "Payment Status",
                ["Pending", "Paid", "Overdue"]
            )

            submitted = st.form_submit_button(
                "Create Invoice"
            )

            if submitted:

                new_id = (
                    f"INV-{1001 + len(st.session_state.invoices)}"
                )

                new_invoice = {
                    "Invoice ID": new_id,
                    "Company": company,
                    "Date": date.today(),
                    "Amount": amount,
                    "Status": status
                }

                st.session_state.invoices.append(
                    new_invoice
                )

                st.session_state.audit_logs.append({
                    "Event": "Invoice Generated",
                    "Company": company,
                    "Action": "CREATE",
                    "Date": str(date.today()),
                    "Status": "Recorded"
                })

                st.success("Invoice created successfully!")

                st.rerun()

    st.subheader("All Invoices")

    invoice_df = pd.DataFrame(
        st.session_state.invoices
    )

    search = st.text_input(
        "🔍 Search Invoice or Company"
    )

    if search:

        invoice_df = invoice_df[
            invoice_df.astype(str).apply(
                lambda row: row.str.contains(
                    search,
                    case=False,
                    regex=False
                ).any(),
                axis=1
            )
        ]

    st.dataframe(
        invoice_df,
        use_container_width=True,
        hide_index=True
    )


# =====================================================
# 8. TENANT MANAGEMENT
# =====================================================

elif page == "Tenants":

    st.title("🏢 Tenant Management")

    st.caption(
        "Manage multiple company workspaces."
    )

    with st.expander("➕ Register New Tenant"):

        with st.form("tenant_form"):

            company = st.text_input(
                "Company Name"
            )

            plan = st.selectbox(
                "Subscription Plan",
                [
                    "Starter",
                    "Growth",
                    "Business",
                    "Enterprise"
                ]
            )

            users = st.number_input(
                "Number of Users",
                min_value=1,
                value=1
            )

            submitted = st.form_submit_button(
                "Register Tenant"
            )

            if submitted:

                if company.strip():

                    new_tenant = {
                        "Tenant ID": (
                            f"TEN-{len(st.session_state.tenants)+1:03d}"
                        ),
                        "Company": company.strip(),
                        "Plan": plan,
                        "Users": users,
                        "Status": "Active"
                    }

                    st.session_state.tenants.append(
                        new_tenant
                    )

                    st.session_state.audit_logs.append({
                        "Event": "Tenant Registered",
                        "Company": company.strip(),
                        "Action": "REGISTER",
                        "Date": str(date.today()),
                        "Status": "Recorded"
                    })

                    st.success(
                        "Tenant registered successfully!"
                    )

                    st.rerun()

                else:
                    st.error("Please enter a company name.")

    st.subheader("Registered Companies")

    tenant_df = pd.DataFrame(
        st.session_state.tenants
    )

    st.dataframe(
        tenant_df,
        use_container_width=True,
        hide_index=True
    )


# =====================================================
# 9. LEDGER AUDIT
# =====================================================

elif page == "Ledger Audit":

    st.title("🔐 Ledger Audit")

    st.caption(
        "Monitor billing records and audit activities."
    )

    st.success("Audit event dashboard is available.")

    audit_df = pd.DataFrame(
        st.session_state.audit_logs
    )

    st.subheader("Audit History")

    st.dataframe(
        audit_df,
        use_container_width=True,
        hide_index=True
    )

    st.info(
        "Production audit events must be stored in a "
        "protected backend and cryptographically verified."
    )


# =====================================================
# 10. SECURITY CENTRE
# =====================================================

elif page == "Security":

    st.title("🛡️ Security Centre")

    st.caption(
        "Review LedgerGuard security controls."
    )

    security_items = [
        ("Tenant Data Isolation", "Configured in demo"),
        ("Role-Based Access Control", "Requires backend"),
        ("API Gateway Protection", "Requires backend"),
        ("Audit Monitoring", "Demo display"),
        ("AES-256 Encryption", "Requires implementation"),
        ("Cryptographic Key Management", "Requires implementation")
    ]

    for name, status in security_items:

        col1, col2 = st.columns([3, 1])

        col1.write("🔒 " + name)

        if "Requires" in status:
            col2.warning(status)
        else:
            col2.info(status)

    st.warning(
        "This page displays planned controls. "
        "It does not activate encryption or security by itself."
    )


# =====================================================
# 11. SETTINGS
# =====================================================

elif page == "Settings":

    st.title("⚙️ Workspace Settings")

    st.subheader("Company Information")

    workspace = st.text_input(
        "Workspace Name",
        value="Acme Corporation"
    )

    admin = st.text_input(
        "Administrator",
        value="Admin User"
    )

    currency = st.selectbox(
        "Default Currency",
        ["INR (₹)", "USD ($)", "EUR (€)"]
    )

    if st.button("Save Settings"):

        st.success("Demo settings updated successfully!")


# =====================================================
# 12. FOOTER
# =====================================================

st.divider()

st.caption(
    "🛡️ LedgerGuard | Dynamic Multi-Tenant Billing Engine"
)

st.caption(
    "Development Prototype | Version 1.0"
)
