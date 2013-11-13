import logging
import os
from threading import Lock
import uuid
from M2Crypto import X509, EVP, RSA, ASN1
import OpenSSL
import Pyro4
import sqlite3
from hashlib import sha1
import time

RSA_BITS = 1024

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
        self.log = self.init_log()
        self.log.info("Initializing CoreRPC")
        self.lock = Lock()

    def init_log(self):
        log = logging.getLogger("appseclab_core")
        log.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        #ch.setLevel(logging.DEBUG)

        #ch1 = logging.StreamHandler()
        #ch1.setLevel(logging.ERROR)

        log.addHandler(ch)
        #self.log.addHandler(ch1)
        log.info("Initialized CoreRPC logger")
        return log

    def _db_connect(self):
        self.log.debug("BEGIN _db_connect()")

        try:
            connection = sqlite3.connect("/tmp/appseclab.db")
            connection.row_factory = sqlite3.Row
        except Exception as e:
            self.log.error(e.message)
            raise
        self.log.info("Connected to the database")

        self.log.debug("END _db_connect() end")

        return connection

    def _hash_password(self, password):
        self.log.debug("BEGIN/END _get_password(password=***)")
        return sha1(password).hexdigest()

    def _get_user(self, uid, password=None):
        self.log.debug("BEGIN _get_user(uid=%s, password=%s)", uid, password)

        db = self._db_connect()
        c = db.cursor()

        try:
            if password:
                c.execute("SELECT uid, lastname, firstname, email FROM users WHERE uid = ? AND pwd = ?",
                          (uid, self._hash_password(password)))
            else:
                c.execute("SELECT uid, lastname, firstname, email FROM users WHERE uid = ?", (uid,))
        except Exception as e:
            self.log.error("_get_user(uid=%s, password=%s): %s", uid, password, e.message)
            raise

        self.log.debug("END _get_user(uid=%s, password=%s)", uid, password)

        return c.fetchone()

    def _create_session(self, uid):
        self.log.debug("BEGIN _create_session(uid=%s)", uid)

        db = self._db_connect()
        c = db.cursor()
        session_id = str(uuid.uuid4())

        try:
            stmt = "INSERT INTO sessions (sid, uid) VALUES (?, ?)", (session_id, uid);
            self.log.info("Inserting new session. Statement: %s", stmt)
            c.execute(stmt)
            db.commit()
        except Exception as e:
            self.log.error("_create_session(uid=%s): %s", uid, e.message)
            raise

        self.log.debug("END _create_session(uid=%s)", uid)

        return session_id

    def _get_session(self, session_id):
        self.log.debug("BEGIN _get_session(session_id=%s)", session_id)

        db = self._db_connect()
        c = db.cursor()

        try:
            stmt = "SELECT sid, uid FROM sessions WHERE sid = ?", (session_id,)
            self.log.info(stmt)
            c.execute(stmt)
        except Exception as e:
            self.log.error("_get_session(session_id=%s): %s", session_id, e.message)
            raise

        self.log.debug("END _get_session(session_id=%s)", session_id)
        return c.fetchone()

    def _is_certificate_revoked(self, certificate_id):
        self.log.debug("BEGIN _is_certificate_revoked(certificate_id=%s)", certificate_id)

        db = self._db_connect()
        c = db.cursor()

        try:
            stmt = "SELECT revoked FROM certificates WHERE id = ?", (certificate_id,)
            self.log.info(stmt)
            c.execute(stmt)
        except Exception as e:
            self.log.error("_is_certificate_revoked(certificate_id=%s): ", certificate_id,  e.message)
            raise

        self.log.debug("END _is_certificate_revoked(certificate_id=%s)", certificate_id)

        return c.fetchone()

    def _delete_session(self, session_id):
        self.log.debug("BEGIN _delete_session(session_id=%s)", session_id)

        db = self._db_connect()
        c = db.cursor()

        try:
            self.log.info("DELETE FROM sessions WHERE sid = ?", (session_id,))
            c.execute("DELETE FROM sessions WHERE sid = ?", (session_id,))
        except Exception as e:
            self.log.error("_delete_session(session_id=%s): %s", session_id, e.message)
            raise

        self.log.debug("END _delete_session(session_id=%s)", session_id)

    def _update_data(self, uid, field, value_new):
        self.log.debug("BEGIN _update_data(uid=%s, field=%s, value_new=%s)", uid, field, value_new)

        db = self._db_connect()
        c = db.cursor()

        # Validate field
        if field not in CHANGEABLE_USER_FIELDS:
            self.log.error("_update_data(uid=%s, field=%s, value_new=%s): Invalid field", uid, field, value_new)
            raise Exception("Invalid field")

        # Get the old value
        c.execute("SELECT ? FROM users WHERE uid = ?", (field, uid))
        value_old = c.fetchone()
        if value_old is None:
            self.log.error("_update_data(uid=%s, field=%s, value_new=%s): Invalid field/user", uid, field,
                           value_new)
            raise Exception("Invalid field/user")

        value_old = value_old[field]

        # Hash passwords
        if field == "pwd":
            value_new = self._hash_password(value_new)

        c.execute("INSERT INTO `update_requests` (uid, field, value_old, value_new) VALUES (?, ?, ?, ?)", (
            uid, field, value_old, value_new
        ))

        self.log.debug("END _update_data(uid=%s, field=%s, value_new=%s)", uid, field, value_new)

    def credential_login(self, user_id, password):
        self.log.debug("BEGIN credential_login(user_id=%s, password=***)", user_id)

        user = self._get_user(user_id, password)
        if user is None:
            self.log.warn("credential_login(user_id=%s, password=***): Invalid credentials", user_id)
            raise Exception("invalid credentials")
        session_id = self._create_session(user["uid"])
        self.log.info("credential_login(user_id=%s, password=***): Login successful", user_id)

        self.log.debug("END credential_login(user_id=%s, password=***)", user_id)
        return session_id

    def validate_session(self, session_id):
        self.log.debug("BEGIN validate_session(session_id=%s)", session_id)

        session = self._get_session(session_id)
        if session is None:
            self.log.warn("validate_session(session_id=%s): Invalid session", session_id)
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            self.log.warn("validate_session(session_id=%s): Invalid user", session_id)
            raise Exception("Invalid user")
        user_data = {"uid": user["uid"],
                     "lastname": user["lastname"],
                     "firstname": user["firstname"],
                     "email": user["email"]}

        self.log.debug("END validate_session(session_id=%s)", session_id)
        return user_data

    def kill_session(self, session_id):
        self.log.debug("BEGIN kill_session(session_id=%s)", session_id)

        self._delete_session(session_id)

        self.log.debug("END kill_session(session_id=%s)", session_id)
        return True

    def update_data(self, session_id, field, value_new):
        self.log.debug("BEGIN update_data(session_id=%s, field=%s, value_new=%s)", session_id, field, value_new)

        session = self._get_session(session_id)
        if session is None:
            self.log.error("update_data(session_id=%s, field=%s, value_new=%s): Invalid session", session_id, field,
                           value_new)
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            self.log.error("update_data(session_id=%s, field=%s, value_new=%s): Invalid user", session_id, field,
                           value_new)
            raise Exception("Invalid user")
        self._update_data(user["uid"], field, value_new)
        # TODO: Revoke certificates

        self.log.debug("END update_data(session_id=%s, field=%s, value_new=%s)", session_id, field, value_new)

    def get_crl(self):
        self.log.debug("BEGIN get_crl()")

        with self.lock:
            if os.path.isfile(os.path.join(PKI_DIRECTORY, CRL_FILENAME)):
                crl = file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "rb").read()
            else:
                crl = ""

        self.log.debug("END get_crl()")
        return crl

    def get_certificate(self, session_id, certificate_id):
        self.log.debug("BEGIN get_certificate(session_id=%s, certificate_id=%s)", session_id, certificate_id)

        session = self._get_session(session_id)
        if session is None:
            self.log.error("get_certificate(session_id=%s, certificate_id=%s): Invalid session", session_id,
                           certificate_id)
            raise Exception("Invalid session")
        certificate = self._get_certificate(certificate_id)
        if certificate["uid"] != session["uid"]:
            self.log.error("get_certificate(session_id=%s, certificate_id=%s): Not your certificate", session_id,
                           certificate_id)
            raise Exception("Not your certificate")

        self.log.debug("END get_certificate(session_id=%s, certificate_id=%s)", session_id, certificate_id)
        return certificate

    def get_certificates(self, session_id):
        self.log.debug("BEGIN get_certificates(session_id=%s)", session_id)

        session = self._get_session(session_id)
        if session is None:
            self.log.error("get_certificates(session_id=%s): Invalid session", session_id)
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            self.log.error("get_certificates(session_id=%s): Invalid user", session_id)
            raise Exception("Invalid user")

        self.log.debug("END get_certificates(session_id=%s)", session_id)
        return self._get_certificates(user["uid"])

    def create_certificate(self, session_id, title, description):
        self.log.debug("BEGIN create_certificate(session_id=%s, title=%s, description=%s)")

        session = self._get_session(session_id)
        if session is None:
            self.log.error("create_certificate(session_id=%s, title=%s, description=%s): Invalid session")
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            self.log.error("create_certificate(session_id=%s, title=%s, description=%s): Invalid user")
            raise Exception("Invalid user")

        # Generate a new key
        k = OpenSSL.crypto.PKey()
        k.generate_key(OpenSSL.crypto.TYPE_DSA, 1024)

        certificate = OpenSSL.crypto.X509()
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
        ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                        file(os.path.join(PKI_DIRECTORY, KEY_FILENAME), "rb").read())
        ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                          file(os.path.join(PKI_DIRECTORY, CERT_FILENAME), "rb").read())

        # Set certificate issuer and sign the certificate
        certificate.set_issuer(ca_cert.get_subject())
        certificate.sign(ca_key, "sha1")

        certificate_data = {
            "certificate": OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate),
            "key": OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k)
        }
        self._store_certificate(user["uid"], certificate_data, title, description)

        self.log.debug("END create_certificate(session_id=%s, title=%s, description=%s)")
        return certificate_data
    """
    def create_certificate_m2(self, session_id, title, description):

        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            raise Exception("Invalid user")

        certificate = X509.X509()

        # create issuer
        subject = certificate.get_subject()
        subject.C = "CH"
        subject.CN = "%s \"%s\" %s" % (user["firstname"], user["uid"], user["lastname"])
        subject.ST = 'Zurich'
        subject.L = 'Zurich'
        subject.O = 'iMovies'
        subject.OU = 'Users'

        #generate RSA keypair
        pk = EVP.PKey()
        rsa = RSA.gen_key(RSA_BITS, 65537, lambda: None)
        pk.assign_rsa(rsa)

        #set valid-date
        t = long(time.time())
        now = ASN1.ASN1_UTCTIME()
        now.set_time(t)

        # expires in one year from know
        expire = ASN1.ASN1_UTCTIME()
        expire.set_time(t + 365 * 24 * 60 * 60)

        certificate.set_not_before(now)
        certificate.set_not_after(expire)
        certificate.set_pubkey(pk)
        certificate.set_subject(subject)
        certificate.set_serial_number(self._get_serial_number())
        #certificate.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
        certificate.add_ext(X509.new_extension('nsComment', str(description)))

        ca_certificate = X509.load_cert(os.path.join(PKI_DIRECTORY, CERT_FILENAME), X509.FORMAT_PEM)
        ca_key = EVP.load_key(os.path.join(PKI_DIRECTORY, KEY_FILENAME))

        certificate.sign(ca_key, 'sha1')

        #print certificate.as_text();

        certificate_data = {
            "certificate": certificate.as_pem(),
            "key": pk.as_pem(None)
        }

        self._store_certificate(user["uid"], certificate_data, title, description)

        return certificate_data"""

    # TODO: check if certificate is still valid (time) or if its on the revocation list
    def verify_certificate(self, certificate):
        self.log.debug("BEGIN verify_certificate(certificate=...)")

        cert_object = X509.load_cert_string(str(certificate), X509.FORMAT_PEM)
        ca_key = EVP.load_key(os.path.join(PKI_DIRECTORY, KEY_FILENAME))

        verify_result = cert_object.verify(ca_key)
        description = ""

        if verify_result == 1:
            verify_result_text = "Valid!"
            description = "This is a valid certificate, signed by the CA"
        else:
            verify_result_text = "Invalid!"
            description = "This is an invalid certificate, no details available"

        verification_data = {
            "status": verify_result,
            "status_text": verify_result_text,
            "description": description
        }

        self.log.debug("END verify_certificate(certificate=...)")
        return verification_data

    def revoke_certificate(self, session_id, certificate_id):
        self.log.debug("BEGIN revoke_certificate(session_id=%s, certificate_id=%s)", session_id, certificate_id)

        session = self._get_session(session_id)
        if session is None:
            self.log.error("revoke_certificate(session_id=%s, certificate_id=%s): Invalid session", session_id,
                           certificate_id)
            raise Exception("Invalid session")
        certificate = self._get_certificate(certificate_id)
        if certificate["uid"] != session["uid"]:
            self.log.error("revoke_certificate(session_id=%s, certificate_id=%s): Invalid user", session_id,
                           certificate_id)
            raise Exception("Invalid user")
        if certificate["revoked"] == "TRUE": # SQLite has no booleans
            self.log.error("revoke_certificate(session_id=%s, certificate_id=%s): Certificate already revoked",
                           session_id, certificate_id)
            raise Exception("Certificate already revoked")

        certificate_instance = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate["certificate"])

        # TODO: Hacky shit. PLZ FIX ME!!!!!
        ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                file(os.path.join(PKI_DIRECTORY, KEY_FILENAME), "rb").read())
        ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                file(os.path.join(PKI_DIRECTORY, CERT_FILENAME), "rb").read())


        '''This optional field describes the version of the encoded CRL.  When
        extensions are used, as required by this profile, this field MUST be
        present and MUST specify version 2 (the integer value is 1).'''
        revoked = OpenSSL.crypto.Revoked()
        revoked.set_reason(None)  # TODO: Change this

        hexno = '%x' % certificate_instance.get_serial_number()

        revoked.set_rev_date(time.strftime("%Y%m%d%H%M%S"))
        revoked.set_serial(hexno)

        with self.lock:
            try:
                if os.path.isfile(os.path.join(PKI_DIRECTORY, CRL_FILENAME)):
                    crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "rb").read())
                else:
                    crl = OpenSSL.crypto.CRL()

                crl.add_revoked(revoked)
                file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "wb").write(crl.export(ca_cert, ca_key))
            except Exception as e:
                self.log.error("revoke_certificate(session_id=%s, certificate_id=%s): %s", session_id, certificate_id,
                               e.message)
                raise
        self._revoke_certificate(certificate_id)

        self.log.debug("END revoke_certificate(session_id=%s, certificate_id=%s)", session_id, certificate_id)

        return 1

    def _store_certificate(self, user_id, certificate_data, title, description):
        self.log.debug("BEGIN _store_certificate(user_id=%s, certificate_data=..., title=%s, description=...", user_id,
                       title)

        db = self._db_connect()
        c = db.cursor()
        c.execute("INSERT INTO certificates (uid, title, description, certificate) VALUES (?, ?, ?, ?)",
                  (user_id, title, description, certificate_data["certificate"]))

        self.log.debug("END _store_certificate(user_id=%s, certificate_data=..., title=%s, description=...", user_id,
                       title)
        db.commit()

    def _get_serial_number(self):
        self.log.debug("BEGIN _get_serial_number()")

        db = self._db_connect()
        c = db.cursor()
        # TODO: This is really ugly :D
        c.execute("SELECT COUNT(*) as serial_number FROM certificates")  # Assuming no certs are deleted!

        self.log.debug("END _get_serial_number()")
        return c.fetchone()["serial_number"] + 1

    def _get_certificate(self, certificate_id):
        self.log.debug("BEGIN _get_certificate_(certificate_id=%s)", certificate_id)

        db = self._db_connect()
        c = db.cursor()
        c.execute("SELECT id, uid, revoked, title, description, certificate FROM certificates WHERE id = ?", (certificate_id,))

        self.log.debug("END _get_certificate_(certificate_id=%s)", certificate_id)
        return dict(c.fetchone())

    def _get_certificates(self, uid):
        self.log.debug("BEGIN _get_certificates(uid=%s)", uid)

        db = self._db_connect()
        c = db.cursor()
        c.execute("SELECT id, uid, revoked, title, description, certificate FROM certificates WHERE uid = ?", (uid,))
        certs = [dict(cert) for cert in c.fetchall()]

        self.log.debug("END _get_certificates(uid=%s)", uid)
        return certs

    def _revoke_certificate(self, certificate_id):
        self.log.debug("BEGIN _revoke_certificate(certificate_id=%s)", certificate_id)

        db = self._db_connect()
        c = db.cursor()
        c.execute("UPDATE certificates SET revoked = 'TRUE' WHERE id = ?", (certificate_id,))
        db.commit()

        self.log.debug("END _revoke_certificate(certificate_id=%s)", certificate_id)

def main():
    d = Pyro4.Daemon()
    ns = Pyro4.locateNS()  # Needs a NameServer running: python -m Pyro4.naming in shell
    uri = d.register(CoreRPC())
    ns.register("core", uri)
    print "Ready!!!!"
    d.requestLoop()


if __name__ == "__main__":
    main()