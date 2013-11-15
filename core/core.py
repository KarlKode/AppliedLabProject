import logging
import os
from threading import Lock
from M2Crypto import X509, EVP
import OpenSSL
import Pyro4
import time
from datetime import datetime
from db import DBSession
from models import User, Session, UpdateRequest, hash_pwd

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
        self.log = None
        self.init_log()
        self.lock = Lock()
        self.log.info("Initializing CoreDB")

    def init_log(self):
        self.log = logging.getLogger("appseclab_core")
        self.log.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        #ch.setLevel(logging.DEBUG)

        #ch1 = logging.StreamHandler()
        #ch1.setLevel(logging.ERROR)

        self.log.addHandler(ch)
        #self.log.addHandler(ch1)
        self.log.info("Initialized CoreRPC logger")

    def get_session(self, dbs, session_id):
        session = dbs.query(Session).filter_by(Session.id == session_id).fetchone()
        session.updated = datetime.now()
        try:
            dbs.add(session)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened
        return session

    def credential_login(self, user_id, password):
        self.log.debug("BEGIN credential_login(user_id=%s, password=***)", user_id)

        dbs = DBSession()

        user = dbs.query(User).filter_by(User.uid == user_id, User.pwd == hash_pwd(password)).fetch_one()
        if user is None:
            self.log.warn("credential_login(user_id=%s, password=***): Invalid credentials", user_id)
            raise Exception("invalid credentials")

        session = Session(user.uid)

        try:
            dbs.add(session)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.info("credential_login(user_id=%s, password=***): Login successful", user_id)

        self.log.debug("END credential_login(user_id=%s, password=***)", user_id)

        return session.id

    def validate_session(self, session_id):
        self.log.debug("BEGIN validate_session(session_id=%s)", session_id)

        dbs = DBSession()

        session = self.get_session(dbs, session_id)
        if session is None:
            self.log.warn("validate_session(session_id=%s): Invalid session", session_id)
            raise Exception("Invalid session")
        # TODO: Update session timestamp

        self.log.debug("END validate_session(session_id=%s)", session_id)
        return session.user.data()

    def kill_session(self, session_id):
        self.log.debug("BEGIN kill_session(session_id=%s)", session_id)

        dbs = DBSession()

        session = self.get_session(dbs, session_id)
        if session is None:
            self.log.warn("validate_session(session_id=%s): Invalid session", session_id)
            raise Exception("Invalid session")

        self.log.debug("END kill_session(session_id=%s)", session_id)
        return True

    def update_data(self, session_id, field, value_new):
        self.log.debug("BEGIN update_data(session_id=%s, field=%s, value_new=%s)", session_id, field, value_new)

        dbs = DBSession()

        session = self.get_session(dbs, session_id)

        if field == "lastname":
            value_old = session.user.lastname
        elif field == "firstname":
            value_old = session.user.firstname
        elif field == "email":
            value_old = session.user.email
        elif field == "pwd":
            value_old = "***"
            value_new = hash_pwd(value_new)
        else:
            self.log.error("update_data(uid=%s, field=%s, value_new=%s): Invalid field", session.user.uid, field,
                           value_new)
            raise Exception("Invalid field")

        update_request = UpdateRequest(session.user.uid, field, None, value_new)

        try:
            dbs.add(update_request)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        # TODO: Revoke certificates?

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

        dbs = DBSession()

        session = self.get_session(dbs, session_id)
        if session is None:
            self.log.error("get_certificate(session_id=%s, certificate_id=%s): Invalid session", session_id,
                           certificate_id)
            raise Exception("Invalid session")
        certificate = self.db.get_certificate(certificate_id)
        if certificate["uid"] != session["uid"]:
            self.log.error("get_certificate(session_id=%s, certificate_id=%s): Not your certificate", session_id,
                           certificate_id)
            raise Exception("Not your certificate")

        self.log.debug("END get_certificate(session_id=%s, certificate_id=%s)", session_id, certificate_id)
        return certificate

    def get_certificates(self, session_id):
        self.log.debug("BEGIN get_certificates(session_id=%s)", session_id)

        session = self.db.get_session(session_id)
        if session is None:
            self.log.error("get_certificates(session_id=%s): Invalid session", session_id)
            raise Exception("Invalid session")
        user = self.db.get_user(session["uid"])
        if user is None:
            self.log.error("get_certificates(session_id=%s): Invalid user", session_id)
            raise Exception("Invalid user")

        self.log.debug("END get_certificates(session_id=%s)", session_id)
        return self.db.get_certificates(user["uid"])

    def create_certificate(self, session_id, title, description):
        self.log.debug("BEGIN create_certificate(session_id=%s, title=%s, description=%s)")

        session = self.db.get_session(session_id)
        if session is None:
            self.log.error("create_certificate(session_id=%s, title=%s, description=%s): Invalid session")
            raise Exception("Invalid session")
        user = self.db.get_user(session["uid"])
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
        certificate.set_serial_number(self.db.get_serial_number())  # TODO: Lock the database?
        certificate.gmtime_adj_notBefore(0)
        certificate.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 365 days

        extensions = [OpenSSL.crypto.X509Extension("crlDistributionPoints", True, "URI:http://example.com/crl.pem")]
        certificate.add_extensions(extensions)


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
        self.db.store_certificate(user["uid"], certificate_data, title, description)

        self.log.debug("END create_certificate(session_id=%s, title=%s, description=%s)")
        return certificate_data

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

        session = self.db.get_session(session_id)
        if session is None:
            self.log.error("revoke_certificate(session_id=%s, certificate_id=%s): Invalid session", session_id,
                           certificate_id)
            raise Exception("Invalid session")
        certificate = self.db.get_certificate(certificate_id)
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
        self.db.revoke_certificate(certificate_id)

        self.log.debug("END revoke_certificate(session_id=%s, certificate_id=%s)", session_id, certificate_id)

        return 1

    def admin_certificate_login(self):
        pass  # TODO

    def admin_get_certificate(self, admin_session_id, certificate_id):
        pass  # TODO

    def admin_get_certificates(self, admin_session_id):
        pass  # TODO

    def admin_get_update_requests(self, admin_session_id):
        pass  # TODO

    def admin_reject_update_request(self, admin_session_id, update_request_id):
        pass  # TODO

    def admin_accept_update_request(self, admin_session_id, update_request_id):
        pass  # TODO

    def admin_revoke_certificate(self, admin_session_id, certificate_id):
        pass  # TODO


def main():
    d = Pyro4.Daemon()
    ns = Pyro4.locateNS()  # Needs a NameServer running: python -m Pyro4.naming in shell
    uri = d.register(CoreRPC())
    ns.register("core", uri)
    d.requestLoop()


if __name__ == "__main__":
    main()