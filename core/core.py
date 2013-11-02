import logging
from random import randint
import uuid
import Pyro4
import sqlite3
from hashlib import sha1


CHANGEABLE_USER_FIELDS = (
    'lastname',
    'firstname',
    'email',
    'pwd'
)


class CoreRPC(object):
    def __init__(self):
        self.sessions = {}
        self.log = logging.getLogger("appseclab_core")
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        self.log.addHandler(ch)

    def _db_connect(self):
        return sqlite3.connect("/tmp/appseclab.db")

    def _hash_password(self, password):
        return sha1(password).hexdigest()

    def _get_user(self, uid, password=None):
        db = self._db_connect()
        c = db.cursor()
        if password:
            c.execute("SELECT * FROM users WHERE uid = ? AND pwd = ?", (uid, self._hash_password(password)))
        else:
            c.execute("SELECT * FROM users WHERE uid = ?", (uid,))
        return c.fetchone()

    def _create_session(self, uid):
        db = self._db_connect()
        c = db.cursor()
        session_id = uuid.uuid4()
        c.execute("INSERT INTO sessions (sid, uid) VALUES (?, ?)", (session_id, uid))
        db.commit()
        return session_id

    def _get_session(self, session_id):
        db = self._db_connect()
        c = db.cursor()
        c.execute("SELECT sid, uid FROM sessions WHERE sid = ?", (session_id,))
        return c.fetchone()

    def _delete_session(self, session_id):
        db = self._db_connect()
        c = db.cursor()
        c.execute("DELETE FROM sessions WHERE sid = ?", (session_id,))
        return c.rowcount

    def _update_data(self, uid, field, value_new):
        db = self._db_connect()
        c = db.cursor()
        # Validate field
        if field not in CHANGEABLE_USER_FIELDS:
            raise Exception("Invalid field")
        c.execute("SELECT ? FROM users WHERE uid = ?", (field, uid))
        value_old = c.fetchone()
        if value_old is None:
            raise Exception("Invalid field or user?!?")
        value_old = value_old[field]
        if field == "pwd":
            value_new = self._hash_password(value_new)
        c.execute("INSERT INTO `update_requests` (uid, field, value_old, value_new) VALUES (?, ?, ?, ?)", (
            uid, field, value_old, value_new
        ))

    def credential_login(self, username, password):
        self.log.info("credential_login(%s, ***)" % (username,))
        user = self._get_user(username, password)
        print user
        if user is None:
            self.log.warn("Invalid login attempt: %s" % (username,))
            raise Exception("invalid credentials")
        session_id = self._create_session(user["uid"])
        self.log.info("User %s logged in with session %s" % (username, session_id))
        return session_id

    def validate_session(self, session_id):
        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        return session["uid"]

    def kill_session(self, session_id):
        self._delete_session(session_id)

    def update_data(self, session_id, field, value_new):
        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            raise Exception("Invalid user")
        self._update_data(user["uid"], field, value_new)

    def create_certificate(self, session_id):
        pass


def main():
    d = Pyro4.Daemon()
    ns = Pyro4.locateNS()  # Needs a NameServer running: python -m Pyro4.naming in shell
    uri = d.register(CoreRPC())
    ns.register("core", uri)
    print "Ready!!!!"
    d.requestLoop()

if __name__ == "__main__":
    main()