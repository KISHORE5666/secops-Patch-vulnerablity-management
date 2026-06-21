from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps
from config import Config
from models import db, User, Asset, Vulnerability, VulnerabilityScan, Patch
from datetime import datetime, date

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ── Role Decorator ────────────────────────────────────────────────────────────

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ── Severity Engine ───────────────────────────────────────────────────────────

SEVERITY_CONFIG = {
    'critical':      {'color': '#b71c1c', 'bg': '#ffebee', 'risk_score': 10, 'priority': 1},
    'high':          {'color': '#e65100', 'bg': '#fff3e0', 'risk_score': 7,  'priority': 2},
    'medium':        {'color': '#f57f17', 'bg': '#fff8e1', 'risk_score': 4,  'priority': 3},
    'low':           {'color': '#2e7d32', 'bg': '#e8f5e9', 'risk_score': 2,  'priority': 4},
    'informational': {'color': '#1565c0', 'bg': '#e3f2fd', 'risk_score': 1,  'priority': 5},
}

def classify_severity(cvss_score):
    """Auto-classify severity from CVSS score."""
    if cvss_score is None:
        return 'informational'
    if cvss_score >= 9.0:
        return 'critical'
    elif cvss_score >= 7.0:
        return 'high'
    elif cvss_score >= 4.0:
        return 'medium'
    elif cvss_score > 0:
        return 'low'
    return 'informational'

def calculate_risk_score(vuln):
    """Calculate risk score based on severity + status."""
    base = SEVERITY_CONFIG.get(vuln.severity, {}).get('risk_score', 1)
    multiplier = 1.0 if vuln.status == 'open' else 0.5 if vuln.status == 'in_progress' else 0.1
    return round(base * multiplier, 1)

app.jinja_env.globals['SEVERITY_CONFIG'] = SEVERITY_CONFIG
app.jinja_env.globals['calculate_risk_score'] = calculate_risk_score


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    total_vulns       = Vulnerability.query.count()
    critical_vulns    = Vulnerability.query.filter_by(severity='critical').count()
    high_vulns        = Vulnerability.query.filter_by(severity='high').count()
    medium_vulns      = Vulnerability.query.filter_by(severity='medium').count()
    low_vulns         = Vulnerability.query.filter_by(severity='low').count()
    open_vulns        = Vulnerability.query.filter_by(status='open').count()
    in_progress_vulns = Vulnerability.query.filter_by(status='in_progress').count()
    resolved_vulns    = Vulnerability.query.filter_by(status='resolved').count()
    total_assets      = Asset.query.count()
    total_scans       = VulnerabilityScan.query.count()
    recent_vulns      = Vulnerability.query.order_by(Vulnerability.created_at.desc()).limit(8).all()

    # Trend data - last 6 months count
    from sqlalchemy import func, extract
    trend_data = []
    for i in range(5, -1, -1):
        from datetime import timedelta
        import calendar
        today = date.today()
        month = (today.month - i - 1) % 12 + 1
        year  = today.year - ((today.month - i - 1) // 12)
        count = Vulnerability.query.filter(
            extract('month', Vulnerability.created_at) == month,
            extract('year',  Vulnerability.created_at) == year
        ).count()
        trend_data.append({'month': calendar.month_abbr[month], 'count': count})

    return render_template('dashboard.html',
        total_vulns=total_vulns, critical_vulns=critical_vulns,
        high_vulns=high_vulns, medium_vulns=medium_vulns, low_vulns=low_vulns,
        open_vulns=open_vulns, in_progress_vulns=in_progress_vulns, resolved_vulns=resolved_vulns,
        total_assets=total_assets, total_scans=total_scans,
        recent_vulns=recent_vulns, trend_data=trend_data)


# ── Asset Management ──────────────────────────────────────────────────────────

@app.route('/assets')
@login_required
def assets_list():
    assets = Asset.query.all()
    return render_template('assets/list.html', assets=assets)

@app.route('/assets/add', methods=['GET', 'POST'])
@login_required
@role_required('super_admin', 'security_admin')
def assets_add():
    if request.method == 'POST':
        asset = Asset(
            asset_name=request.form.get('asset_name'),
            ip_address=request.form.get('ip_address'),
            operating_system=request.form.get('operating_system'),
            owner=request.form.get('owner'),
            asset_type=request.form.get('asset_type')
        )
        db.session.add(asset)
        db.session.commit()
        flash('Asset added successfully.', 'success')
        return redirect(url_for('assets_list'))
    return render_template('assets/add.html')

@app.route('/assets/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('super_admin', 'security_admin')
def assets_edit(id):
    asset = Asset.query.get_or_404(id)
    if request.method == 'POST':
        asset.asset_name       = request.form.get('asset_name')
        asset.ip_address       = request.form.get('ip_address')
        asset.operating_system = request.form.get('operating_system')
        asset.owner            = request.form.get('owner')
        asset.asset_type       = request.form.get('asset_type')
        db.session.commit()
        flash('Asset updated.', 'success')
        return redirect(url_for('assets_list'))
    return render_template('assets/edit.html', asset=asset)

@app.route('/assets/delete/<int:id>', methods=['POST'])
@login_required
@role_required('super_admin')
def assets_delete(id):
    asset = Asset.query.get_or_404(id)
    db.session.delete(asset)
    db.session.commit()
    flash('Asset deleted.', 'success')
    return redirect(url_for('assets_list'))


# ── Vulnerability Management ──────────────────────────────────────────────────

@app.route('/vulnerabilities')
@login_required
def vuln_list():
    severity_filter = request.args.get('severity', '')
    status_filter   = request.args.get('status', '')
    search          = request.args.get('search', '')
    query = Vulnerability.query
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if search:
        query = query.filter(
            Vulnerability.cve_id.ilike(f'%{search}%') |
            Vulnerability.title.ilike(f'%{search}%') |
            Vulnerability.affected_asset.ilike(f'%{search}%')
        )
    vulns  = query.order_by(Vulnerability.created_at.desc()).all()
    assets = Asset.query.all()
    return render_template('vulnerabilities/list.html',
        vulns=vulns, assets=assets,
        severity_filter=severity_filter, status_filter=status_filter, search=search)

@app.route('/vulnerabilities/add', methods=['GET', 'POST'])
@login_required
@role_required('super_admin', 'security_admin')
def vuln_add():
    assets = Asset.query.all()
    if request.method == 'POST':
        cvss_raw     = request.form.get('cvss_score')
        cvss         = float(cvss_raw) if cvss_raw else None
        disc_raw     = request.form.get('discovered_date')
        discovered   = date.fromisoformat(disc_raw) if disc_raw else None
        asset_id_raw = request.form.get('asset_id')
        asset_id     = int(asset_id_raw) if asset_id_raw else None

        # Auto-classify severity if not manually set
        severity = request.form.get('severity')
        if not severity or severity == 'auto':
            severity = classify_severity(cvss)

        vuln = Vulnerability(
            cve_id=request.form.get('cve_id'),
            title=request.form.get('title'),
            description=request.form.get('description'),
            severity=severity,
            cvss_score=cvss,
            affected_asset=request.form.get('affected_asset'),
            discovered_date=discovered,
            status=request.form.get('status', 'open'),
            remediation_plan=request.form.get('remediation_plan'),
            asset_id=asset_id
        )
        db.session.add(vuln)
        db.session.commit()
        flash('Vulnerability added.', 'success')
        return redirect(url_for('vuln_list'))
    return render_template('vulnerabilities/add.html', assets=assets,
                           severity_config=SEVERITY_CONFIG)

@app.route('/vulnerabilities/view/<int:id>')
@login_required
def vuln_view(id):
    vuln = Vulnerability.query.get_or_404(id)
    risk_score = calculate_risk_score(vuln)
    history    = RemediationHistory.query.filter_by(vuln_id=id).order_by(RemediationHistory.created_at.desc()).all()
    return render_template('vulnerabilities/view.html', vuln=vuln,
                           risk_score=risk_score, history=history,
                           severity_config=SEVERITY_CONFIG)

@app.route('/vulnerabilities/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('super_admin', 'security_admin')
def vuln_edit(id):
    vuln   = Vulnerability.query.get_or_404(id)
    assets = Asset.query.all()
    if request.method == 'POST':
        old_status = vuln.status
        cvss_raw   = request.form.get('cvss_score')
        disc_raw   = request.form.get('discovered_date')
        asset_raw  = request.form.get('asset_id')

        vuln.cve_id           = request.form.get('cve_id')
        vuln.title            = request.form.get('title')
        vuln.description      = request.form.get('description')
        vuln.severity         = request.form.get('severity')
        vuln.cvss_score       = float(cvss_raw) if cvss_raw else None
        vuln.affected_asset   = request.form.get('affected_asset')
        vuln.discovered_date  = date.fromisoformat(disc_raw) if disc_raw else None
        vuln.status           = request.form.get('status')
        vuln.remediation_plan = request.form.get('remediation_plan')
        vuln.asset_id         = int(asset_raw) if asset_raw else None

        # Log status change to remediation history
        new_status = vuln.status
        if old_status != new_status:
            note = f"Status changed from {old_status} to {new_status} by {current_user.username}"
            history = RemediationHistory(vuln_id=id, action=note, performed_by=current_user.username, status_change=f"{old_status} → {new_status}")
            db.session.add(history)

        db.session.commit()
        flash('Vulnerability updated.', 'success')
        return redirect(url_for('vuln_view', id=vuln.id))
    return render_template('vulnerabilities/edit.html', vuln=vuln, assets=assets,
                           severity_config=SEVERITY_CONFIG)

@app.route('/vulnerabilities/delete/<int:id>', methods=['POST'])
@login_required
@role_required('super_admin')
def vuln_delete(id):
    vuln = Vulnerability.query.get_or_404(id)
    db.session.delete(vuln)
    db.session.commit()
    flash('Vulnerability deleted.', 'success')
    return redirect(url_for('vuln_list'))


# ── Remediation Tracking ──────────────────────────────────────────────────────

@app.route('/vulnerabilities/<int:id>/remediate', methods=['POST'])
@login_required
@role_required('super_admin', 'security_admin')
def vuln_remediate(id):
    vuln       = Vulnerability.query.get_or_404(id)
    old_status = vuln.status
    new_status = request.form.get('status')
    note       = request.form.get('note', '')

    vuln.status = new_status
    history = RemediationHistory(
        vuln_id=id,
        action=note or f"Status updated to {new_status}",
        performed_by=current_user.username,
        status_change=f"{old_status} → {new_status}"
    )
    db.session.add(history)
    db.session.commit()
    flash('Remediation status updated.', 'success')
    return redirect(url_for('vuln_view', id=id))


# ── Scan Records ──────────────────────────────────────────────────────────────

@app.route('/scans')
@login_required
def scans_list():
    scans = VulnerabilityScan.query.order_by(VulnerabilityScan.scan_date.desc()).all()
    return render_template('vulnerabilities/scans.html', scans=scans)

@app.route('/scans/add', methods=['GET', 'POST'])
@login_required
@role_required('super_admin', 'security_admin')
def scans_add():
    if request.method == 'POST':
        scan = VulnerabilityScan(
            scan_name=request.form.get('scan_name'),
            scanner_type=request.form.get('scanner_type'),
            findings_count=int(request.form.get('findings_count') or 0)
        )
        db.session.add(scan)
        db.session.commit()
        flash('Scan record added.', 'success')
        return redirect(url_for('scans_list'))
    return render_template('vulnerabilities/scans_add.html')


# ── API: Severity auto-classify ───────────────────────────────────────────────

@app.route('/api/classify-severity')
@login_required
def api_classify_severity():
    cvss = request.args.get('cvss', type=float)
    return jsonify({'severity': classify_severity(cvss)})


# ── DB Init ───────────────────────────────────────────────────────────────────

from models import RemediationHistory

def seed_default_users():
    if User.query.count() == 0:
        for u in [
            {'username': 'superadmin', 'email': 'superadmin@secops.com', 'role': 'super_admin',    'password': 'Admin@123'},
            {'username': 'secadmin',   'email': 'secadmin@secops.com',   'role': 'security_admin', 'password': 'Admin@123'},
            {'username': 'analyst',    'email': 'analyst@secops.com',    'role': 'analyst',        'password': 'Admin@123'},
        ]:
            user = User(username=u['username'], email=u['email'], role=u['role'])
            user.set_password(u['password'])
            db.session.add(user)
        db.session.commit()
        print("Default users created.")

with app.app_context():
    db.create_all()
    seed_default_users()



# ── Patch Management ──────────────────────────────────────────────────────────
from models import Patch, PatchAsset

@app.route('/patches')
@login_required
def patch_list():
    patches = Patch.query.order_by(Patch.created_at.desc()).all()
    return render_template('patches/list.html', patches=patches)

@app.route('/patches/add', methods=['GET','POST'])
@login_required
@role_required('super_admin','security_admin')
def patch_add():
    if request.method == 'POST':
        rd = request.form.get('release_date')
        p = Patch(patch_name=request.form.get('patch_name'),
                  patch_version=request.form.get('patch_version'),
                  vendor=request.form.get('vendor'),
                  release_date=date.fromisoformat(rd) if rd else None,
                  severity=request.form.get('severity','medium'),
                  description=request.form.get('description'))
        db.session.add(p); db.session.commit()
        flash('Patch added.','success')
        return redirect(url_for('patch_list'))
    return render_template('patches/add.html')

@app.route('/patches/view/<int:id>')
@login_required
def patch_view(id):
    patch  = Patch.query.get_or_404(id)
    assets = Asset.query.all()
    assignments = PatchAsset.query.filter_by(patch_id=id).all()
    return render_template('patches/view.html', patch=patch, assets=assets, assignments=assignments)

@app.route('/patches/delete/<int:id>', methods=['POST'])
@login_required
@role_required('super_admin')
def patch_delete(id):
    db.session.delete(Patch.query.get_or_404(id)); db.session.commit()
    flash('Patch deleted.','success')
    return redirect(url_for('patch_list'))

@app.route('/patches/assign/<int:patch_id>', methods=['POST'])
@login_required
@role_required('super_admin','security_admin')
def patch_assign(patch_id):
    asset_ids = request.form.getlist('asset_ids')
    sched_raw = request.form.get('scheduled_at')
    sched = datetime.fromisoformat(sched_raw) if sched_raw else None
    for aid in asset_ids:
        exists = PatchAsset.query.filter_by(patch_id=patch_id, asset_id=int(aid)).first()
        if not exists:
            db.session.add(PatchAsset(patch_id=patch_id, asset_id=int(aid),
                                      scheduled_at=sched, assigned_by=current_user.username))
    db.session.commit()
    flash(f'{len(asset_ids)} asset(s) assigned.','success')
    return redirect(url_for('patch_view', id=patch_id))

@app.route('/patches/status/<int:assignment_id>', methods=['POST'])
@login_required
@role_required('super_admin','security_admin')
def patch_status_update(assignment_id):
    pa = PatchAsset.query.get_or_404(assignment_id)
    pa.status = request.form.get('status')
    pa.notes  = request.form.get('notes','')
    if pa.status == 'successful': pa.deployed_at = datetime.utcnow()
    db.session.commit()
    flash('Status updated.','success')
    return redirect(url_for('patch_view', id=pa.patch_id))

@app.route('/patches/dashboard')
@login_required
def patch_dashboard():
    from sqlalchemy import func
    total      = Patch.query.count()
    pending    = PatchAsset.query.filter_by(status='pending').count()
    successful = PatchAsset.query.filter_by(status='successful').count()
    failed     = PatchAsset.query.filter_by(status='failed').count()
    total_a    = PatchAsset.query.count()
    compliance = round((successful/total_a*100),1) if total_a else 0
    missing    = Asset.query.count() * total - total_a
    # trend last 6 months
    import calendar
    trend = []
    for i in range(5,-1,-1):
        from datetime import timedelta
        today = date.today()
        month = (today.month-i-1)%12+1
        year  = today.year-((today.month-i-1)//12)
        c = PatchAsset.query.filter(
            db.extract('month',PatchAsset.created_at)==month,
            db.extract('year', PatchAsset.created_at)==year,
            PatchAsset.status=='successful').count()
        trend.append({'month':calendar.month_abbr[month],'count':c})
    recent = PatchAsset.query.order_by(PatchAsset.updated_at.desc()).limit(10).all()
    return render_template('patches/dashboard.html',
        total=total, pending=pending, successful=successful,
        failed=failed, compliance=compliance, missing=missing,
        trend=trend, recent=recent)

@app.route('/patches/report')
@login_required
def patch_report():
    report_type = request.args.get('type','all')
    if report_type == 'missing':
        # assets with no successful patch assignment
        assigned_asset_ids = [pa.asset_id for pa in PatchAsset.query.filter_by(status='successful').all()]
        assets = Asset.query.filter(~Asset.id.in_(assigned_asset_ids)).all() if assigned_asset_ids else Asset.query.all()
        assignments = []
    elif report_type == 'successful':
        assignments = PatchAsset.query.filter_by(status='successful').order_by(PatchAsset.deployed_at.desc()).all()
        assets = []
    elif report_type == 'failed':
        assignments = PatchAsset.query.filter_by(status='failed').all()
        assets = []
    else:
        assignments = PatchAsset.query.order_by(PatchAsset.created_at.desc()).all()
        assets = []
    return render_template('patches/report.html',
        assignments=assignments, assets=assets, report_type=report_type)

if __name__ == '__main__':
    app.run(debug=True)
