from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

import settings

engine = create_engine(settings.DB)
session_factory = sessionmaker(bind=engine)
DBSession = scoped_session(session_factory)

class CoreDB(object):


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



    def create_admin_session(self, uid):
        self.log.debug("BEGIN create_admin_session(uid=%s)", uid)

        db = self.connect()
        c = db.cursor()
        session_id = str(uuid.uuid4())

        try:
            stmt = "INSERT INTO admin_sessions (sid, uid) VALUES (?, ?)", (session_id, uid);
            self.log.info("Inserting new admin session. Statement: %s", stmt)
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