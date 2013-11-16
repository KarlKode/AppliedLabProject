import hashlib
import uuid
from datetime import datetime
from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    uid = Column(String(64), nullable=False, default="", primary_key=True)
    lastname = Column(String(64), nullable=False, default="")
    firstname = Column(String(64), nullable=False, default="")
    email = Column(String(64), nullable=False, default="")
    pwd = Column(String(64), nullable=False, default="")

    certificates = relation("Certificate", backref="user", lazy="dynamic")

    def __repr__(self):
        return "<User %r, %r, %r, %r>" % (self.uid, self.lastname, self.firstname, self.email)

    def data(self):
        return {"uid": self.uid,
                "lastname": self.lastname,
                "firstname": self.firstname,
                "email": self.email}


def hash_pwd(pwd):
    return hashlib.sha1(pwd).hexdigest()


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(40), primary_key=True)
    uid = Column(String(64), ForeignKey("users.uid"))
    updated = Column(DateTime)

    user = relation("User", backref="sessions", lazy=False)

    def __init__(self, uid):
        self.id = str(uuid.uuid4())
        self.uid = uid
        self.updated = datetime.now()

    def __repr__(self):
        return "<Session %r, %r, %r>" % (self.id, self.uid, self.updated)


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id = Column(String(40), primary_key=True)
    uid = Column(String(64), ForeignKey("users.uid"))
    updated = Column(DateTime, default=func.now(), onupdate=func.now())

    user = relation("User", backref="admin_sessions", lazy=True)

    def __init__(self, uid):
        self.id = str(uuid.uuid4())
        self.uid = uid

    def __repr__(self):
        return "<Session %r, %r, %r>" % (self.id, self.uid, self.updated)


class UpdateRequest(Base):
    __tablename__ = "update_requests"

    id = Column(Integer, primary_key=True)
    uid = Column(String(64), ForeignKey("users.uid"))
    field = Column(String(10))
    value_old = Column(String(64))
    value_new = Column(String(64))

    user = relation("User", backref="update_requests", lazy=False)

    def __init__(self, uid, field, value_old, value_new):
        self.uid = uid
        self.field = field
        self.value_old = value_old
        self.value_new = value_new

    def __repr__(self):
        return "<UpdateRequest %r, %r, %r>" % (self.id, self.uid, self.field)

    def data(self):
        return {"id": self.id,
                "uid": self.uid,
                "user": self.user.data(),
                "field": self.field,
                "value_old": self.value_old,
                "value_new": self.value_new}


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True)
    uid = Column(String(64), ForeignKey("users.uid"))
    revoked = Column(Boolean)
    title = Column(String(100))
    description = Column(String(500))
    certificate = Column(Text)

    def __init__(self, uid, title, description, certificate):
        self.uid = uid
        self.revoked = False
        self.title = title
        self.description = description
        self.certificate = certificate

    def __repr__(self):
        return "<Certificate %r, %r, %r>" % (self.id, self.uid, self.title)

    def data(self):
        return {"id": self.id,
                "uid": self.uid,
                "user": self.user.data(),
                "email": self.user.email,
                "revoked": self.revoked,
                "title": self.title,
                "description": self.description,
                "certificate": self.certificate}