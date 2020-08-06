"""Database module."""
from uuid import uuid4

from app.main.extensions import db

Column = db.Column


class CRUDMixin:
    """Mixin adds CRUD operations."""

    @classmethod
    def create(cls, **kwargs):
        """Create and save new record"""
        instance = cls(**kwargs)
        return instance.save()

    def delete(self, commit=True):
        """Delete record."""
        db.session.delete(self)
        return commit and db.session.commit()

    def update(self, commit=True, **kwargs):
        """Update fields of record."""
        for k, v in kwargs.items():
            setattr(self, k, v)
        return commit and self.save() or self

    def save(self, commit=True):
        """Save record."""
        db.session.add(self)
        if commit:
            db.session.commit()
        return self


class Model(CRUDMixin, db.Model):
    """Updated base model with CRUD methods"""

    __abstract__ = True


class SurrogatePK:
    """Mixin that adds surrogate uuid primary key 'id'"""

    __table_args__ = {"extend_existing": True}

    id = Column(db.String(), primary_key=True, default=lambda: str(uuid4()))

    @classmethod
    def get_by_id(cls, record_id):
        if isinstance(record_id, str):
            return cls.query.get(record_id)
        return None
