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
        self.log = logging.getLogger("appseclab_core")
        self.log.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        #ch.setLevel(logging.DEBUG)

        #ch1 = logging.StreamHandler()
        #ch1.setLevel(logging.ERROR)

        self.log.addHandler(ch)
        #self.log.addHandler(ch1)

        self.log.info("constructor initialized")
        self.lock = Lock()

    def _db_connect(self):
        self.log.debug("_db_connect() begin")

        try:
            connection = sqlite3.connect("/tmp/appseclab.db")
            connection.row_factory = sqlite3.Row
        except Exception as e:
            self.log.error(e.message)
            raise e

        self.log.debug("_db_connect() end")

        return connection

    def _hash_password(self, password):
        return sha1(password).hexdigest()

    def _get_user(self, uid, password=None):
        self.log.debug("_get_user() begins: uid: %s ", uid)

        db = self._db_connect()
        c = db.cursor()

        try:
            if password:
                c.execute("SELECT uid, lastname, firstname, email FROM users WHERE uid = ? AND pwd = ?",
                          (uid, self._hash_password(password)))
            else:
                c.execute("SELECT uid, lastname, firstname, email FROM users WHERE uid = ?", (uid,))
        except Exception as e:
            self.log.error("Error in function _get_user(): " + e.message)
            raise e

        self.log.debug("_get_user() ends: uid: %s ", uid)

        return c.fetchone()

    def _create_session(self, uid):
        self.log.debug("_create_session() begins: uid: %s ", uid)

        db = self._db_connect()
        c = db.cursor()
        session_id = str(uuid.uuid4())
        self.log.debug("_create_session() ends: uid: %s ", uid)

        stmt = "INSERT INTO sessions (sid, uid) VALUES (?, ?)", (session_id, uid);
        self.log.debug("add new session_id with stmt: " + stmt)

        try:
            c.execute(stmt)
            db.commit()
        except Exception as e:
            self.log.error("Error in function _create_session(): " + e.message)
            raise e

        self.log.debug("_create_session() ends: uid: %s ", uid)

        return session_id

    def _get_session(self, session_id):
        db = self._db_connect()
        c = db.cursor()

        try:
            self.log.debug("SELECT sid, uid FROM sessions WHERE sid = ?", (session_id,))
            c.execute("SELECT sid, uid FROM sessions WHERE sid = ?", (session_id,))
        except Exception as e:
            self.log.error("Error in function _get_session(): " + e.message)
            raise e

        return c.fetchone()

    def _is_certificate_revoked(self, certificate_id):
        db = self._db_connect()
        c = db.cursor()

        try:
            self.log.debug("SELECT revoked FROM certificates WHERE id = ?", (certificate_id,))
            c.execute("SELECT revoked FROM certificates WHERE id = ?", (certificate_id,))
        except Exception as e:
            self.log.error("Error in function _is_certificate_revoked() with certificate_id %s: " + e.message, certificate_id)
            raise e

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
            self.log.error("Invalid session_id: %s", session_id)
            raise Exception("Invalid session")
        user = self._get_user(session["uid"])
        if user is None:
            self.log.error("Invalid user")
            raise Exception("Invalid user")
        self._update_data(user["uid"], field, value_new)
        # TODO: Revoke certificates

    def get_crl(self):
        self.lock.acquire()
        try:
            if os.path.isfile(os.path.join(PKI_DIRECTORY, CRL_FILENAME)):
                crl = file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "rb").read()
            else:
                crl = ""
        finally:
            self.lock.release()

        return crl

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

        return certificate_data

    #TODO: check if certificate is still valid (time) or if its on the revocation list
    def verify_certificate(self, certificate):
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

        return verification_data

    def revoke_certificate(self, session_id, certificate_id):
        session = self._get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        certificate = self._get_certificate(certificate_id)
        if certificate["uid"] != session["uid"]:
            raise Exception("Not your certificate")
        if certificate["revoked"] == 'TRUE':
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

        self.lock.acquire()
        try:
            if os.path.isfile(os.path.join(PKI_DIRECTORY, CRL_FILENAME)):
                crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "rb").read())
            else:
                crl = OpenSSL.crypto.CRL()

            crl.add_revoked(revoked)
            file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "wb").write(crl.export(ca_cert, ca_key))
        except Exception as e:
            print e
        finally:
            self.lock.release() # release lock, no matter what

        print crl.export(ca_cert, ca_key, OpenSSL.crypto.FILETYPE_TEXT)

        self._revoke_certificate(certificate_id)

        return 1

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
        c.execute("UPDATE certificates SET revoked = 'TRUE' WHERE id = ?", (certificate_id,))
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