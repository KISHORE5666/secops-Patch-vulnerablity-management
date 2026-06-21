from app import app
from models import db, Asset, VulnerabilityScan, Vulnerability, RemediationHistory, Patch, PatchAsset
from datetime import datetime, date, timedelta
import random

with app.app_context():
    print("Seeding database with sample data...")

    # Clear existing data (optional, but good for resetting)
    # db.drop_all()
    # db.create_all()

    if Asset.query.count() > 0:
        print("Data already exists. Skipping seed.")
        exit(0)

    # 1. Add Assets
    assets = [
        Asset(asset_name="Web-Server-01", ip_address="10.0.0.12", operating_system="Ubuntu 22.04 LTS", owner="DevOps Team", asset_type="server"),
        Asset(asset_name="DB-Primary-Node", ip_address="10.0.0.55", operating_system="RedHat Enterprise Linux 8", owner="Database Admin", asset_type="database"),
        Asset(asset_name="Employee-Laptop-042", ip_address="192.168.1.104", operating_system="Windows 11 Pro", owner="John Doe", asset_type="workstation"),
        Asset(asset_name="Auth-Service-Pod", ip_address="10.1.2.4", operating_system="Alpine Linux", owner="Security Team", asset_type="container")
    ]
    db.session.add_all(assets)
    db.session.commit()

    # 2. Add Vulnerability Scans
    scans = [
        VulnerabilityScan(scan_name="Weekly External Network Scan", scan_date=datetime.utcnow() - timedelta(days=2), scanner_type="Nessus", findings_count=3),
        VulnerabilityScan(scan_name="Container Image Deep Scan", scan_date=datetime.utcnow() - timedelta(hours=12), scanner_type="Trivy", findings_count=1)
    ]
    db.session.add_all(scans)
    db.session.commit()

    # 3. Add Vulnerabilities
    vulns = [
        Vulnerability(
            cve_id="CVE-2023-38408", title="OpenSSH Forwarded agent vulnerability", 
            description="A flaw was found in OpenSSH's forwarded ssh-agent. An attacker who has compromised the remote server could exploit this to perform arbitrary commands on the local machine.",
            severity="critical", cvss_score=9.8, affected_asset="Web-Server-01", 
            discovered_date=date.today() - timedelta(days=2), status="open", 
            remediation_plan="Upgrade OpenSSH to version 9.3p2 or higher.", 
            asset_id=assets[0].id, scan_id=scans[0].id
        ),
        Vulnerability(
            cve_id="CVE-2021-44228", title="Log4Shell in Authentication Service", 
            description="Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            severity="critical", cvss_score=10.0, affected_asset="Auth-Service-Pod", 
            discovered_date=date.today() - timedelta(days=1), status="in_progress", 
            remediation_plan="Update to log4j-2.15.0 or set formatMsgNoLookups=true.", 
            asset_id=assets[3].id, scan_id=scans[1].id
        ),
        Vulnerability(
            cve_id="CVE-2024-21412", title="Windows Internet Shortcut Files Security Feature Bypass", 
            description="An attacker can craft a malicious Internet Shortcut file that bypasses Mark of the Web (MotW) defenses.",
            severity="high", cvss_score=8.1, affected_asset="Employee-Laptop-042", 
            discovered_date=date.today() - timedelta(days=5), status="resolved", 
            remediation_plan="Apply Microsoft February 2024 Patch Tuesday updates.", 
            asset_id=assets[2].id, scan_id=scans[0].id
        )
    ]
    db.session.add_all(vulns)
    db.session.commit()

    # 4. Add Remediation History
    histories = [
        RemediationHistory(vuln_id=vulns[1].id, action="Investigating exploitability in our container environment.", performed_by="secadmin", status_change="open → in_progress"),
        RemediationHistory(vuln_id=vulns[2].id, action="Applied Windows Update KB5034765 automatically via WSUS.", performed_by="superadmin", status_change="open → resolved")
    ]
    db.session.add_all(histories)
    db.session.commit()

    # 5. Add Patches
    patches = [
        Patch(patch_name="Ubuntu Security Update USN-6235-1", patch_version="1.0.0", vendor="Canonical", release_date=date.today() - timedelta(days=10), severity="critical", description="Fixes OpenSSH vulnerability CVE-2023-38408."),
        Patch(patch_name="Windows 11 Cumulative Update KB5034765", patch_version="OS Build 22631.3155", vendor="Microsoft", release_date=date.today() - timedelta(days=15), severity="high", description="Monthly security update including fix for CVE-2024-21412.")
    ]
    db.session.add_all(patches)
    db.session.commit()

    # 6. Add Patch Assignments
    patch_assignments = [
        PatchAsset(patch_id=patches[0].id, asset_id=assets[0].id, status="pending", scheduled_at=datetime.utcnow() + timedelta(hours=2), assigned_by="superadmin"),
        PatchAsset(patch_id=patches[1].id, asset_id=assets[2].id, status="successful", deployed_at=datetime.utcnow() - timedelta(days=1), notes="Auto-deployed via Intune.", assigned_by="system")
    ]
    db.session.add_all(patch_assignments)
    db.session.commit()

    print("Successfully added mock data!")
