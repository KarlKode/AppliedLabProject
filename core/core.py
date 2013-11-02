import logging
import os
import uuid
import Pyro4
import sqlite3
from OpenSSL import crypto
from hashlib import sha1


PKI_DIRECTORY = "./pki"
CRL_FILENAME = "ca.crl"
KEY_FILENAME = "ca.key"
CERT_FILENAME = "ca.crt"

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
        self.log.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        self.log.addHandler(ch)

    def _db_connect(self):
        connection = sqlite3.connect("/tmp/appseclab.db")
        connection.row_factory = sqlite3.Row
        return connection

    def _hash_password(self, password):
        return sha1(password).hexdigest()

    def _get_user(self, uid, password=None):
        db = self._db_connect()
        c = db.cursor()
        if password:
            c.execute("SELECT uid, lastname, firstname, email FROM users WHERE uid = ? AND pwd = ?",
                      (uid, self._hash_password(password)))
        else:
            c.execute("SELECT uid, lastname, firstname, email FROM users WHERE uid = ?", (uid,))
        return c.fetchone()

    def _create_session(self, uid):
        db = self._db_connect()
        c = db.cursor()
        session_id = str(uuid.uuid4())
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

    def credential_login(self, user_id, password):
        self.log.info("credential_login(%s, ***)" % (user_id,))
        user = self._get_user(user_id, password)
        if user is None:
            self.log.warn("Invalid login attempt: %s" % (user_id,))
            raise Exception("invalid credentials")
        session_id = self._create_session(user["uid"])
        self.log.info("User %s logged in with session %s" % (user_id, session_id))
        return session_id

    def validate_session(self, session_id):
        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            raise Exception("Invalid user")
        user_data = {"uid": user["uid"],
                     "lastname": user["lastname"],
                     "firstname": user["firstname"],
                     "email": user["email"]}
        return user_data

    def kill_session(self, session_id):
        self._delete_session(session_id)
        return True

    def update_data(self, session_id, field, value_new):
        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            raise Exception("Invalid user")
        self._update_data(user["uid"], field, value_new)
        # TODO: Revoke certificates

    def get_crl(self):
        return file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "rb").read()

    def get_certificate(self, session_id, certificate_id):
        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        certificate = self._get_certificate(certificate_id)
        if certificate["uid"] != session["uid"]:
            raise Exception("Not your certificate")
        return certificate

    def get_certificates(self, session_id):
        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            raise Exception("Invalid user")
        return self._get_certificates(user["uid"])

    def create_certificate(self, session_id, title, description):
        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            raise Exception("Invalid user")

        # Generate a new key
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_DSA, 1024)

        certificate = crypto.X509()
        subject = certificate.get_subject()  # TODO: We should change this
        subject.countryName = "CH"
        subject.stateOrProvinceName = "Zurich"
        subject.localityName = "Zurich"
        subject.organizationName = "iMovies"
        subject.organizationalUnitName = "Users"
        subject.commonName = "%s \"%s\" %s" % (user["firstname"], user["uid"], user["lastname"])
        subject.emailAddress = user["email"]

        certificate.set_pubkey(k)
        #certificate.set_subject(subject)
        certificate.set_serial_number(self._get_serial_number())  # TODO: Lock the database?
        certificate.gmtime_adj_notBefore(0)
        certificate.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 365 days


        # TODO: Hacky shit. PLZ FIX ME!!!!!
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                        file(os.path.join(PKI_DIRECTORY, KEY_FILENAME), "rb").read())
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                          file(os.path.join(PKI_DIRECTORY, CERT_FILENAME), "rb").read())

        # Set certificate issuer and sign the certificate
        certificate.set_issuer(ca_cert.get_subject())
        certificate.sign(ca_key, "sha1")

        certificate_data = {
            "certificate": crypto.dump_certificate(crypto.FILETYPE_PEM, certificate),
            "key": crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
        }
        self._store_certificate(user["uid"], certificate_data, title, description)
        return certificate_data

    def revoke_certificate(self, session_id, certificate_id):
        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        certificate = self._get_certificate(certificate_id)
        if certificate["uid"] != session["uid"]:
            raise Exception("Not your certificate")

        certificate_instance = crypto.load_certificate(crypto.FILETYPE_PEM, certificate["certificate"])
        revoked = crypto.Revoked()
        revoked.set_reason(None)  # TODO: Change this
        revoked.set_rev_date(certificate_instance.get_notBefore())
        revoked.set_serial(hex(certificate_instance.get_serial_number()))
        print "lol"
        crl = crypto.load_crl(crypto.FILETYPE_PEM, file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "rb").read())
        print "lol"
        crl.add_revoked(revoked)
        print "lol"

        # TODO: Hacky shit. PLZ FIX ME!!!!!
        print "lol"
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                        file(os.path.join(PKI_DIRECTORY, KEY_FILENAME), "rb").read())
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                          file(os.path.join(PKI_DIRECTORY, CERT_FILENAME), "rb").read())
        print "doneaaaa"
        file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "wb").write(crl.export(ca_cert, ca_key))
        print "done"

        return self._revoke_certificate(certificate_id)

    def _store_certificate(self, user_id, certificate_data, title, description):
        db = self._db_connect()
        c = db.cursor()
        c.execute("INSERT INTO certificates (uid, title, description, certificate) VALUES (?, ?, ?, ?)",
                  (user_id, title, description, certificate_data["certificate"]))
        db.commit()

    def _get_serial_number(self):
        db = self._db_connect()
        c = db.cursor()
        c.execute("SELECT COUNT(*) as serial_number FROM certificates")  # Assuming no certs are deleted!
        return c.fetchone()["serial_number"] + 1

    def _get_certificate(self, certificate_id):
        db = self._db_connect()
        c = db.cursor()
        c.execute("SELECT id, uid, revoked, title, description, certificate FROM certificates WHERE id = ?", (certificate_id,))
        return dict(c.fetchone())

    def _get_certificates(self, uid):
        db = self._db_connect()
        c = db.cursor()
        c.execute("SELECT id, uid, revoked, title, description, certificate FROM certificates WHERE uid = ?", (uid,))
        certs = []
        for cert in c.fetchall():
            certs.append(dict(cert))
        return certs

    def _revoke_certificate(self, certificate_id):
        db = self._db_connect()
        c = db.cursor()
        c.execute("UPDATE certificates SET revoked = TRUE WHERE id = ?", (certificate_id,))
        db.commit()


def main():
    d = Pyro4.Daemon()
    ns = Pyro4.locateNS()  # Needs a NameServer running: python -m Pyro4.naming in shell
    uri = d.register(CoreRPC())
    ns.register("core", uri)
    print "Ready!!!!"
    d.requestLoop()


if __name__ == "__main__":
    main()