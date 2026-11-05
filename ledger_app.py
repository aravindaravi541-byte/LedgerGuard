
import streamlit as st
import pandas as pd
from datetime import date, timedelta

# ---------------- PAGE CONFIGURATION ----------------

st.set_page_config(
    page_title="LedgerGuard Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- CUSTOM CSS ----------------

st.markdown("""
<style>
.stApp {
    background-color: #f5f6fb;
}

[data-testid="stSidebar"] {
    background-color: #10172a;
}

[data-testid="stSidebar"] * {
    color: #ffffff !important;
}

.main-title {
    font-size: 30px;
    font-weight: 800;
    color: #20243a;
}

.sub-title {
    color: #858b9d;
    font-size: 14px;
}

.metric-card {
    background: white;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #e7e9f0;
    margin-bottom: 10px;
}

.metric-label {
    color: #858b9d;
    font-size: 13px;
}

.metric-value {
    color: #272b40;
    font-size: 27px;
    font-weight: bold;
}

.metric-change {
    color: #20a477;
    font-size: 12px;
}

.section-card {
    background: white;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #e7e9f0;
    margin-bottom: 20px;
}

.security-banner {
    background: #e9e8ff;
    padding: 15px;
    border-radius: 10px;
    color: #4c48a5;
    margin-bottom: 20px;
}

div.stButton > button {
    background-color: #5c55ca;
    color: white;
    border-radius: 7px;
    border: none;
    padding: 9px 18px;
}

div.stButton > button:hover {
    background-color: #4540a8;
    color: white;
}

</style>
""", unsafe_allow_html=True)


# ---------------- SAMPLE DATABASE ----------------

if "invoices" not in st.session_state:
    st.session_state.invoices = [
        {
            "Invoice ID": "INV-1001",
            "Tenant": "Northstar Logistics",
            "Date": date.today(),
            "Amount": 48500,
            "Status": "Paid"
        },
        {
            "Invoice ID": "INV-1002",
            "Tenant": "Aster Healthcare",
            "Date": date.today(),
            "Amount": 32000,
            "Status": "Pending"
        },
        {
            "Invoice ID": "INV-1003",
            "Tenant": "Bluepeak Retail",
            "Date": date.today(),
            "Amount": 76250,
            "Status": "Paid"
        },
        {
            "Invoice ID": "INV-1004",
            "Tenant": "Crestline Labs",
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


# ---------------- SIDEBAR ----------------

st.sidebar.markdown("# 🛡️ LedgerGuard")
st.sidebar.caption("SECURE BILLING ENGINE")
st.sidebar.divider()

st.sidebar.markdown("### Workspace")
st.sidebar.info("🏢 Acme Corporation")

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
st.sidebar.markdown("### Workspace Admin")
st.sidebar.write("👤 Admin User")
st.sidebar.caption("Administrator")


# ---------------- DASHBOARD ----------------

if page == "Dashboard":

    st.markdown(
        '<div class="main-title">Welcome to LedgerGuard 👋</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="sub-title">Manage your billing operations securely.</div>',
        unsafe_allow_html=True
    )

    st.write("")

    st.markdown("""
    <div class="security-banner">
        🛡️ <b>Security Status: Protected</b><br>
        Tenant isolation enabled | Audit monitoring active
    </div>
    """, unsafe_allow_html=True)

    invoices_df = pd.DataFrame(st.session_state.invoices)

    total_revenue = invoices_df[
        invoices_df["Status"] == "Paid"
    ]["Amount"].sum()

    total_invoices = len(invoices_df)

    active_tenants = sum(
        1 for t in st.session_state.tenants
        if t["Status"] == "Active"
    )

    outstanding = invoices_df[
        invoices_df["Status"].isin(["Pending", "Overdue"])
    ]["Amount"].sum()

    # METRICS

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "💰 Total Revenue",
            f"₹{total_revenue:,.0f}",
            "+12.8%"
        )

    with col2:
        st.metric(
            "📄 Total Invoices",
            total_invoices,
            "Billing records"
        )

    with col3:
        st.metric(
            "🏢 Active Tenants",
            active_tenants,
            "Companies"
        )

    with col4:
        st.metric(
            "⏳ Outstanding",
            f"₹{outstanding:,.0f}"
        )

    st.divider()

    # REVENUE CHART

    left, right = st.columns(2)

    with left:
        st.subheader("📊 Revenue Overview")

        chart_data = pd.DataFrame({
            "Month": ["Jun", "Jul", "Aug", "Sep", "Oct", "Nov"],
            "Revenue": [45000, 62000, 58000, 85000, 92000, 105000]
        })

        st.bar_chart(
            chart_data.set_index("Month")
        )

    with right:
        st.subheader("📈 Invoice Status")

        status_count = invoices_df["Status"].value_counts()

        st.bar_chart(status_count)

    st.divider()

    # RECENT INVOICES

    st.subheader("📋 Recent Invoices")

    st.dataframe(
        invoices_df,
        use_container_width=True,
        hide_index=True
    )

    # PLATFORM HEALTH

    st.subheader("⚙️ Platform Health")

    h1, h2, h3 = st.columns(3)

    h1.success("API Gateway: Operational")
    h2.success("Tenant Isolation: Enabled")
    h3.success("Ledger Integrity: Monitoring")


# ---------------- INVOICES ----------------

elif page == "Invoices":

    st.title("📄 Invoice Management")
    st.caption("Create and manage invoices across tenant workspaces.")

    with st.expander("➕ Create New Invoice", expanded=False):

        with st.form("invoice_form"):

            tenant_names = [
                t["Company"] for t in st.session_state.tenants
            ]

            selected_tenant = st.selectbox(
                "Select Company",
                tenant_names
            )

            amount = st.number_input(
                "Invoice Amount (₹)",
                min_value=1,
                step=100
            )

            invoice_status = st.selectbox(
                "Payment Status",
                ["Pending", "Paid", "Overdue"]
            )

            submitted = st.form_submit_button(
                "Create Invoice"
            )

            if submitted:

                new_invoice = {
                    "Invoice ID": f"INV-{1001 + len(st.session_state.invoices)}",
                    "Tenant": selected_tenant,
                    "Date": date.today(),
                    "Amount": amount,
                    "Status": invoice_status
                }

                st.session_state.invoices.append(
                    new_invoice
                )

                st.success("Invoice created successfully!")

                st.rerun()

    st.subheader("All Invoices")

    invoice_df = pd.DataFrame(
        st.session_state.invoices
    )

    search = st.text_input(
        "🔍 Search invoice or company"
    )

    if search:
        invoice_df = invoice_df[
            invoice_df.astype(str).apply(
                lambda row: row.str.contains(
                    search,
                    case=False
                ).any(),
                axis=1
            )
        ]

    st.dataframe(
        invoice_df,
        use_container_width=True,
        hide_index=True
    )


# ---------------- TENANT MANAGEMENT ----------------

elif page == "Tenants":

    st.title("🏢 Tenant Management")
    st.caption("Manage multiple company workspaces.")

    with st.expander("➕ Register New Tenant"):

        with st.form("tenant_form"):

            company = st.text_input(
                "Company Name"
            )

            plan = st.selectbox(
                "Subscription Plan",
                ["Starter", "Growth", "Business", "Enterprise"]
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
                        "Tenant ID": f"TEN-{len(st.session_state.tenants) + 1:03d}",
                        "Company": company,
                        "Plan": plan,
                        "Users": users,
                        "Status": "Active"
                    }

                    st.session_state.tenants.append(
                        new_tenant
                    )

                    st.success("Tenant registered successfully!")

                    st.rerun()

                else:
                    st.error("Please enter a company name.")

    st.subheader("Registered Companies")

    tenants_df = pd.DataFrame(
        st.session_state.tenants
    )

    st.dataframe(
        tenants_df,
        use_container_width=True,
        hide_index=True
    )


# ---------------- LEDGER AUDIT ----------------

elif page == "Ledger Audit":

    st.title("🔐 Ledger Audit")
    st.caption("Monitor billing records and audit activities.")

    st.success(
        "Ledger monitoring dashboard is active."
    )

    audit_data = pd.DataFrame([
        {
            "Event": "Invoice Generated",
            "Tenant": "Northstar Logistics",
            "Action": "CREATE",
            "Time": "Today",
            "Status": "Verified"
        },
        {
            "Event": "Payment Received",
            "Tenant": "Aster Healthcare",
            "Action": "PAYMENT",
            "Time": "Today",
            "Status": "Verified"
        },
        {
            "Event": "Tenant Registered",
            "Tenant": "Bluepeak Retail",
            "Action": "REGISTER",
            "Time": "Yesterday",
            "Status": "Verified"
        },
        {
            "Event": "Access Policy Updated",
            "Tenant": "Crestline Labs",
            "Action": "UPDATE",
            "Time": "Yesterday",
            "Status": "Verified"
        }
    ])

    st.subheader("Audit History")

    st.dataframe(
        audit_data,
        use_container_width=True,
        hide_index=True
    )

    st.info(
        "Production audit events should be recorded and hash-verified by the backend."
    )


# ---------------- SECURITY ----------------

elif page == "Security":

    st.title("🛡️ Security Centre")

    st.caption(
        "Monitor security controls and tenant protection."
    )

    st.success("Security monitoring overview")

    security_items = [
        ("Tenant Data Isolation", "Enabled"),
        ("Role Based Access Control", "Enabled"),
        ("API Gateway Protection", "Enabled"),
        ("Audit Monitoring", "Enabled"),
        ("Cryptographic Key Management", "Requires implementation"),
        ("AES-256 Encryption", "Requires implementation")
    ]

    for name, status in security_items:

        col1, col2 = st.columns([3, 1])

        col1.write("🔒 " + name)

        if status == "Enabled":
            col2.success(status)
        else:
            col2.warning(status)


# ---------------- SETTINGS ----------------

elif page == "Settings":

    st.title("⚙️ Settings")

    st.subheader("Workspace Information")

    st.text_input(
        "Workspace Name",
        value="Acme Corporation"
    )

    st.text_input(
        "Administrator",
        value="Admin User"
    )

    st.selectbox(
        "Default Currency",
        ["INR (₹)", "USD ($)", "EUR (€)"]
    )

    if st.button("Save Settings"):
        st.success("Demo settings updated.")


# ---------------- FOOTER ----------------

st.sidebar.divider()

st.sidebar.caption(
    "LedgerGuard v1.0 | Secure Billing Engine"
)

st.sidebar.caption(
    "Development Prototype"
)
