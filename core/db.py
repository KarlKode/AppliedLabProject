import hashlib
import logging
import sqlite3
import uuid


class CoreDB(object):
    def __init__(self, settings):
        self.init_log()
        self.settings = settings
        self.log.info("Initialized CoreDB")

    def init_log(self):
        self.log = logging.getLogger("appseclab_core.db")
        #log.setLevel(logging.DEBUG)
        #ch = logging.StreamHandler()
        #ch.setLevel(logging.DEBUG)

        #ch1 = logging.StreamHandler()
        #ch1.setLevel(logging.ERROR)

        #log.addHandler(ch)
        #self.log.addHandler(ch1)
        self.log.info("Initialized CoreDB logger")

    def connect(self):
        self.log.debug("BEGIN connect()")

        try:
            connection = sqlite3.connect(self.settings.get("DB"))
            connection.row_factory = sqlite3.Row
        except Exception as e:
            self.log.error(e.message)
            raise
        self.log.info("Connected to the database")

        self.log.debug("END connect() end")

        return connection

    def hash_password(self, password):
        self.log.debug("BEGIN/END hash_password(password=***)")
        return hashlib.sha1(password).hexdigest()

    def get_user(self, uid, password=None):
        self.log.debug("BEGIN get_user(uid=%s, password=%s)", uid, password)

        db = self.connect()
        c = db.cursor()

        try:
            if password:
                c.execute("SELECT uid, lastname, firstname, email FROM users WHERE uid = ? AND pwd = ?",
                          (uid, self.hash_password(password)))
            else:
                c.execute("SELECT uid, lastname, firstname, email FROM users WHERE uid = ?", (uid,))
        except Exception as e:
            self.log.error("get_user(uid=%s, password=%s): %s", uid, password, e.message)
            raise

        self.log.debug("END get_user(uid=%s, password=%s)", uid, password)

        return c.fetchone()

    def create_session(self, uid):
        self.log.debug("BEGIN create_session(uid=%s)", uid)

        db = self.connect()
        c = db.cursor()
        session_id = str(uuid.uuid4())

        try:
            stmt = "INSERT INTO sessions (sid, uid) VALUES (?, ?)", (session_id, uid);
            self.log.info("Inserting new session. Statement: %s", stmt)
            c.execute(stmt)
            db.commit()
        except Exception as e:
            self.log.error("create_session(uid=%s): %s", uid, e.message)
            raise

        self.log.debug("END create_session(uid=%s)", uid)

        return session_id

    def get_session(self, session_id):
        self.log.debug("BEGIN get_session(session_id=%s)", session_id)

        db = self.connect()
        c = db.cursor()

        try:
            stmt = "SELECT sid, uid FROM sessions WHERE sid = ?", (session_id,)
            self.log.info(stmt)
            c.execute(stmt)
        except Exception as e:
            self.log.error("get_session(session_id=%s): %s", session_id, e.message)
            raise

        self.log.debug("END get_session(session_id=%s)", session_id)
        return c.fetchone()

    def is_certificate_revoked(self, certificate_id):
        self.log.debug("BEGIN is_certificate_revoked(certificate_id=%s)", certificate_id)

        db = self.connect()
        c = db.cursor()

        try:
            stmt = "SELECT revoked FROM certificates WHERE id = ?", (certificate_id,)
            self.log.info(stmt)
            c.execute(stmt)
        except Exception as e:
            self.log.error("is_certificate_revoked(certificate_id=%s): ", certificate_id,  e.message)
            raise

        self.log.debug("END is_certificate_revoked(certificate_id=%s)", certificate_id)

        return c.fetchone()

    def delete_session(self, session_id):
        self.log.debug("BEGIN delete_session(session_id=%s)", session_id)

        db = self.connect()
        c = db.cursor()

        try:
            self.log.info("DELETE FROM sessions WHERE sid = ?", (session_id,))
            c.execute("DELETE FROM sessions WHERE sid = ?", (session_id,))
        except Exception as e:
            self.log.error("delete_session(session_id=%s): %s", session_id, e.message)
            raise

        self.log.debug("END delete_session(session_id=%s)", session_id)

    def update_data(self, uid, field, value_new):
        self.log.debug("BEGIN update_data(uid=%s, field=%s, value_new=%s)", uid, field, value_new)

        db = self.connect()
        c = db.cursor()

        # Validate field
        if field not in self.settings.get("CHANGEABLE_USER_FIELDS"):
            self.log.error("update_data(uid=%s, field=%s, value_new=%s): Invalid field", uid, field, value_new)
            raise Exception("Invalid field")

        # Get the old value
        c.execute("SELECT ? FROM users WHERE uid = ?", (field, uid))
        value_old = c.fetchone()
        if value_old is None:
            self.log.error("update_data(uid=%s, field=%s, value_new=%s): Invalid field/user", uid, field,
                           value_new)
            raise Exception("Invalid field/user")

        value_old = value_old[field]

        # Hash passwords
        if field == "pwd":
            value_new = self.hash_password(value_new)

        c.execute("INSERT INTO `update_requests` (uid, field, value_old, value_new) VALUES (?, ?, ?, ?)", (
            uid, field, value_old, value_new
        ))

        self.log.debug("END update_data(uid=%s, field=%s, value_new=%s)", uid, field, value_new)

    def store_certificate(self, user_id, certificate_data, title, description):
        self.log.debug("BEGIN store_certificate(user_id=%s, certificate_data=..., title=%s, description=...", user_id,
                       title)

        db = self.connect()
        c = db.cursor()
        c.execute("INSERT INTO certificates (uid, title, description, certificate) VALUES (?, ?, ?, ?)",
                  (user_id, title, description, certificate_data["certificate"]))

        self.log.debug("END store_certificate(user_id=%s, certificate_data=..., title=%s, description=...", user_id,
                       title)
        db.commit()

    def get_serial_number(self):
        self.log.debug("BEGIN get_serial_number()")

        db = self.connect()
        c = db.cursor()
        # TODO: This is really ugly :D
        c.execute("SELECT COUNT(*) as serial_number FROM certificates")  # Assuming no certs are deleted!

        self.log.debug("END get_serial_number()")
        return c.fetchone()["serial_number"] + 1

    def get_certificate(self, certificate_id):
        self.log.debug("BEGIN get_certificate_(certificate_id=%s)", certificate_id)

        db = self.connect()
        c = db.cursor()
        c.execute("SELECT id, uid, revoked, title, description, certificate FROM certificates WHERE id = ?", (certificate_id,))

        self.log.debug("END get_certificate_(certificate_id=%s)", certificate_id)
        return dict(c.fetchone())

    def get_certificates(self, uid):
        self.log.debug("BEGIN get_certificates(uid=%s)", uid)

        db = self.connect()
        c = db.cursor()
        c.execute("SELECT id, uid, revoked, title, description, certificate FROM certificates WHERE uid = ?", (uid,))
        certs = [dict(cert) for cert in c.fetchall()]

        self.log.debug("END get_certificates(uid=%s)", uid)
        return certs

    def revoke_certificate(self, certificate_id):
        self.log.debug("BEGIN revoke_certificate(certificate_id=%s)", certificate_id)

        db = self.connect()
        c = db.cursor()
        c.execute("UPDATE certificates SET revoked = 'TRUE' WHERE id = ?", (certificate_id,))
        db.commit()

        self.log.debug("END revoke_certificate(certificate_id=%s)", certificate_id)