import hashlib
import uuid
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

    def __repr__(self):
        return "<User %r, %r, %r, %r>" % (self.uid, self.lastname, self.firstname, self.email)

    def data(self):
        return {"uid": self.uid,
                "lastname": self.lastname,
                "firstname": self.firstname,
                "email": self.email}


def hash_pwd(pwd):
    hashlib.sha1(pwd).hexdigest()


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(40), primary_key=True)
    uid = Column(String(64), ForeignKey("users.uid"))
    updated = Column(DateTime, default=func.now(), onupdate=func.now())

    user = relation("User", backref="sessions", lazy=True)

    def __init__(self, uid):
        self.sid = str(uuid.uuid4())
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

    user = relation("User", backref="update_requests", lazy=True)

    def __init__(self, uid, field, value_old, value_new):
        self.uid = uid
        self.field = field
        self.value_old = value_old
        self.value_new = value_new

    def __repr__(self):
        return "<UpdateRequest %r, %r, %r>" % (self.id, self.uid, self.field)
