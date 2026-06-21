from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(80), unique=True, nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(200), nullable=False)
    role       = db.Column(db.String(20), nullable=False, default='analyst')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Asset(db.Model):
    __tablename__ = 'assets'
    id               = db.Column(db.Integer, primary_key=True)
    asset_name       = db.Column(db.String(100), nullable=False)
    ip_address       = db.Column(db.String(45), nullable=False)
    operating_system = db.Column(db.String(100), nullable=False)
    owner            = db.Column(db.String(100), nullable=False)
    asset_type       = db.Column(db.String(50), default='workstation')
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at       = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    vulnerabilities = db.relationship('Vulnerability', backref='asset', lazy=True)


class VulnerabilityScan(db.Model):
    __tablename__ = 'vulnerability_scans'
    id             = db.Column(db.Integer, primary_key=True)
    scan_name      = db.Column(db.String(200), nullable=False)
    scan_date      = db.Column(db.DateTime, default=datetime.utcnow)
    scanner_type   = db.Column(db.String(50), nullable=False)
    findings_count = db.Column(db.Integer, default=0)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    id               = db.Column(db.Integer, primary_key=True)
    cve_id           = db.Column(db.String(20), nullable=False)
    title            = db.Column(db.String(200), nullable=False)
    description      = db.Column(db.Text, nullable=False)
    severity         = db.Column(db.String(20), nullable=False)
    cvss_score       = db.Column(db.Float, nullable=True)
    affected_asset   = db.Column(db.String(100), nullable=True)
    discovered_date  = db.Column(db.Date, nullable=True)
    status           = db.Column(db.String(20), default='open')
    remediation_plan = db.Column(db.Text, nullable=True)
    asset_id         = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=True)
    scan_id          = db.Column(db.Integer, db.ForeignKey('vulnerability_scans.id'), nullable=True)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at       = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    history = db.relationship('RemediationHistory', backref='vulnerability', lazy=True, cascade='all, delete-orphan')


class RemediationHistory(db.Model):
    __tablename__ = 'remediation_history'
    id            = db.Column(db.Integer, primary_key=True)
    vuln_id       = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False)
    action        = db.Column(db.Text, nullable=False)
    performed_by  = db.Column(db.String(80), nullable=False)
    status_change = db.Column(db.String(50), nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)


class Patch(db.Model):
    __tablename__ = 'patches'
    id           = db.Column(db.Integer, primary_key=True)
    patch_name   = db.Column(db.String(200), nullable=False)
    patch_version= db.Column(db.String(50), nullable=False)
    vendor       = db.Column(db.String(100), nullable=True)
    release_date = db.Column(db.Date, nullable=True)
    severity     = db.Column(db.String(20), default='medium')
    description  = db.Column(db.Text, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    assignments  = db.relationship('PatchAsset', backref='patch', lazy=True, cascade='all, delete-orphan')


class PatchAsset(db.Model):
    __tablename__ = 'patch_assets'
    id          = db.Column(db.Integer, primary_key=True)
    patch_id    = db.Column(db.Integer, db.ForeignKey('patches.id'), nullable=False)
    asset_id    = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    asset       = db.relationship('Asset', backref='patch_assignments')
    status      = db.Column(db.String(20), default='pending')  # pending, scheduled, in_progress, successful, failed, rolled_back
    scheduled_at= db.Column(db.DateTime, nullable=True)
    deployed_at = db.Column(db.DateTime, nullable=True)
    notes       = db.Column(db.Text, nullable=True)
    assigned_by = db.Column(db.String(80), nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
