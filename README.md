# SecOps Management Platform

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-lightgrey.svg)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-red.svg)

A centralized **Security Operations (SecOps) Platform** built with Python and Flask. This platform empowers security teams to gain deep visibility into their IT infrastructure's security posture by streamlining asset management, vulnerability tracking, and patch deployment.

##  Features

* **Centralized Asset Management:** Maintain a detailed inventory of IT assets (servers, databases, workstations, containers) across the organization.
* **Intelligent Vulnerability Tracking:** 
  * Log vulnerabilities (CVEs) and associate them with affected assets.
  * **Auto-classification Engine:** Automatically assigns severity levels (Critical, High, Medium, Low) based on CVSS scores.
  * **Dynamic Risk Scoring:** Calculates risk based on base severity and current remediation status.
* **Patch Management & Orchestration:** Log available patches, schedule deployments, and monitor rollout statuses (Pending, Successful, Failed) to ensure compliance.
* **Remediation Audit Trails:** Comprehensive history of actions taken against vulnerabilities with a clear audit log.
* **Analytics & Dashboards:** Visual overviews of security health, featuring 6-month vulnerability trends, patch compliance rates, and critical open issues.
* **Role-Based Access Control (RBAC):** Secure access using Flask-Login with distinct roles (`super_admin`, `security_admin`, `analyst`).

##  Tech Stack

* **Backend:** Python, Flask
* **Database:** SQLAlchemy (ORM)
* **Authentication:** Flask-Login, Werkzeug Security
* **Frontend:** HTML/CSS (Jinja2 Templating)

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.8+ installed on your machine.
* `pip` (Python package manager).

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/secops-platform.git
cd secops-platform
```

### 2. Create a Virtual Environment (Recommended)
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
Make sure you have your dependencies installed. If you have a `requirements.txt`, run:
```bash
pip install -r requirements.txt
```
*(If you don't have a requirements.txt, you will at minimum need: `Flask`, `Flask-SQLAlchemy`, `Flask-Login`, `Werkzeug`)*

### 4. Initialize and Seed the Database
The application is configured to create the database automatically on the first run. You can also populate it with sample mock data to test the dashboards.
```bash
python seed_data.py
```

### 5. Run the Application
```bash
python app.py
```
The application will start on `http://127.0.0.1:5000/`.

## 🔐 Default Credentials

When the database is initialized, the following default users are created for testing the RBAC features:

| Role | Username | Password |
| :--- | :--- | :--- |
| **Super Admin** | `superadmin` | `Admin@123` |
| **Security Admin** | `secadmin` | `Admin@123` |
| **Analyst** | `analyst` | `Admin@123` |

*Please ensure you change these credentials in a production environment.*

## Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page if you want to contribute.

## 📝 License
This project is licensed under the [MIT License](LICENSE).
