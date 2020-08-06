"""API User model."""
from datetime import datetime

from app.main.database import Model, SurrogatePK, Column, db
from app.main.extensions import bcrypt

from .enum import Role
from .schema import UserSchema


class User(SurrogatePK, Model):
    """API users."""

    __tablename__ = "users"
    username = Column(db.String(80), unique=True, nullable=False)
    email = Column(db.String(80), unique=True, nullable=False)
    password_hash = Column(db.LargeBinary(128), nullable=True)
    active = Column(db.Boolean(), default=False)
    role = Column(db.Enum(Role), default=Role.USER)
    created_at = Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, username, email, password=None, active=None, role=None):
        """Create instance."""
        self.username = username
        self.email = email
        if password:
            self.password = password
        if active is not None:
            self.active = active
        if role is not None:
            self.role = role

    @property
    def password(self):
        """Raise exception if attribute accessed."""
        raise AttributeError("password: write-only attribute")

    @password.setter
    def password(self, value):
        """Set hashed password."""
        self.password_hash = bcrypt.generate_password_hash(value)

    def check_password(self, value):
        """Check candidate password against hashed password."""
        return bcrypt.check_password_hash(self.password_hash, value)

    def to_dict(self):
        """Serialize user instance."""
        schema = UserSchema()
        return schema.dump(self)

    @classmethod
    def get_by_email(cls, email):
        if isinstance(email, str):
            return cls.query.filter_by(email=email).first()
        return None
