import logging
import os
from threading import Lock
from M2Crypto import X509, EVP
import OpenSSL
import Pyro4
import time
from datetime import datetime
from db import DBSession
from models import User, Session, UpdateRequest, hash_pwd, Certificate, AdminSession

RSA_BITS = 1024

PKI_DIRECTORY = "./pki"
CRL_FILENAME = "ca.crl"
KEY_FILENAME = "ca.key"
CERT_FILENAME = "ca.crt"


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
        self.log.debug("BEGIN get_session(session_id=%s)", session_id)

        session = dbs.query(Session).filter_by(Session.id == session_id).fetchone()
        try:
            dbs.add(session)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.debug("END get_session(session_id=%s)", session_id)
        return session

    def validate_session(self, session_id):
        self.log.debug("BEGIN validate_session(session_id=%s)", session_id)

        dbs = DBSession()

        session = self.get_session(dbs, session_id)
        if session is None:
            self.log.warn("validate_session(session_id=%s): Invalid session", session_id)
            raise Exception("Invalid session")

        session.updated = datetime.now()

        try:
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.debug("END validate_session(session_id=%s)", session_id)
        return session.user.data()

    def kill_session(self, session_id):
        self.log.debug("BEGIN kill_session(session_id=%s)", session_id)

        dbs = DBSession()

        session = self.get_session(dbs, session_id)
        if session is None:
            self.log.warn("kill_session(session_id=%s): Invalid session", session_id)
            raise Exception("Invalid session")

        try:
            dbs.delete(session)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.debug("END kill_session(session_id=%s)", session_id)
        return True

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

    def certificate_login(self, certificate):
        pass  # TODO

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

        update_request = UpdateRequest(session.user.uid, field, value_old, value_new)

        try:
            dbs.add(update_request)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        # TODO: Revoke certificates?

        self.log.debug("END update_data(session_id=%s, field=%s, value_new=%s)", session_id, field, value_new)
        return True

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
        certificate = session.user.certificates.filter_by(Certificate.id == certificate_id).fetch_one()
        if certificate is None:
            self.log.error("get_certificat(session_id=%s, certificate_id=%s): Invalid certificate", session_id,
                           certificate_id)

        self.log.debug("END get_certificate(session_id=%s, certificate_id=%s)", session_id, certificate_id)
        return certificate.data()

    def get_certificates(self, session_id):
        self.log.debug("BEGIN get_certificates(session_id=%s)", session_id)

        dbs = DBSession()

        session = self.get_session(dbs, session_id)
        if session is None:
            self.log.error("get_certificates(session_id=%s): Invalid session", session_id)
            raise Exception("Invalid session")

        self.log.debug("END get_certificates(session_id=%s)", session_id)
        # Get the data dictionary for every certificate of the user
        return [certificate.data() for certificate in session.user.certificates.all()]

    def create_certificate(self, session_id, title, description):
        self.log.debug("BEGIN create_certificate(session_id=%s, title=%s, description=%s)")

        dbs = DBSession()

        session = self.get_session(dbs, session_id)
        if session is None:
            self.log.error("create_certificate(session_id=%s, title=%s, description=%s): Invalid session")
            raise Exception("Invalid session")

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
        subject.commonName = "%s \"%s\" %s" % (session.user.firstname, session.user.uid, session.user.lastname)
        subject.emailAddress = session.user.email

        certificate.set_pubkey(k)
        certificate.set_serial_number(
            123)  # TODO: Get current certificate serial number (= number of certificates in the db + 1)
        certificate.gmtime_adj_notBefore(0)  # Now
        certificate.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 365 days

        # TODO: Change crl url
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

        # Get the actual certificate
        certificate_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
        certificate_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k)

        db_certificate = Certificate(session.user.uid, title, description, certificate_pem)

        try:
            dbs.add(db_certificate)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.debug("END create_certificate(session_id=%s, title=%s, description=%s)")
        return {"certificate": certificate_pem, "key": certificate_key}

    # TODO: check if certificate is still valid (time) or if its on the revocation list
    def verify_certificate(self, certificate):
        self.log.debug("BEGIN verify_certificate(certificate=...)")

        cert_object = X509.load_cert_string(str(certificate), X509.FORMAT_PEM)
        ca_key = EVP.load_key(os.path.join(PKI_DIRECTORY, KEY_FILENAME))  # Can be done with the public key!

        verify_result = cert_object.verify(ca_key)

        if verify_result == 1:
            verify_result_text = "Valid"
            description = "The certificate is valid and was signed by the CA."
        else:
            verify_result_text = "Invalid"
            description = "The certificate is invalid. No more details are available."

        verification_data = {
            "status": verify_result,
            "status_text": verify_result_text,
            "description": description
        }

        self.log.debug("END verify_certificate(certificate=...)")
        return verification_data

    def revoke_certificate(self, session_id, certificate_id):
        self.log.debug("BEGIN revoke_certificate(session_id=%s, certificate_id=%s)", session_id, certificate_id)

        dbs = DBSession()

        session = self.get_session(dbs, session_id)
        if session is None:
            self.log.error("revoke_certificate(session_id=%s, certificate_id=%s): Invalid session", session_id,
                           certificate_id)
            raise Exception("Invalid session")

        certificate = session.user.certificates.filter_by(Certificate.id == certificate_id).fetch_one()
        if certificate is None:
            self.log.error("revoke_certificate(session_id=%s, certificate_id=%s): Invalid certificate", session_id,
                           certificate_id)
        if certificate.revoked:
            self.log.error("revoke_certificate(session_id=%s, certificate_id=%s): Certificate already revoked",
                           session_id, certificate_id)
            raise Exception("Certificate already revoked")

        certificate_instance = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate.certificate)

        # TODO: Hacky shit. PLZ FIX ME!!!!!
        ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                file(os.path.join(PKI_DIRECTORY, KEY_FILENAME), "rb").read())
        ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                  file(os.path.join(PKI_DIRECTORY, CERT_FILENAME), "rb").read())

        # This optional field describes the version of the encoded CRL.  When
        # extensions are used, as required by this profile, this field MUST be
        # present and MUST specify version 2 (the integer value is 1).
        revoked = OpenSSL.crypto.Revoked()
        revoked.set_reason(None)  # TODO: Change this
        revoked.set_rev_date(time.strftime("%Y%m%d%H%M%S"))
        revoked.set_serial("%x" % (certificate_instance.get_serial_number(),))

        with self.lock:
            try:
                if os.path.isfile(os.path.join(PKI_DIRECTORY, CRL_FILENAME)):
                    crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM,
                                                  file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "rb").read())
                else:
                    crl = OpenSSL.crypto.CRL()

                crl.add_revoked(revoked)
                file(os.path.join(PKI_DIRECTORY, CRL_FILENAME), "wb").write(crl.export(ca_cert, ca_key))
            except Exception as e:
                self.log.error("revoke_certificate(session_id=%s, certificate_id=%s): %s", session_id, certificate_id,
                               e.message)
                raise

        certificate.revoked = True
        try:
            dbs.add(certificate)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.debug("END revoke_certificate(session_id=%s, certificate_id=%s)", session_id, certificate_id)
        return True

    # ADMIN STUFF #

    def admin_get_session(self, dbs, admin_session_id):
        self.log.debug("BEGIN admin_get_session(admin_session_id=%s)", admin_session_id)

        admin_session = dbs.query(AdminSession).filter_by(AdminSession.id == admin_session_id).fetchone()
        admin_session.updated = datetime.now()
        try:
            dbs.add(admin_session)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.debug("END admin_get_session(admin_session_id=%s)", admin_session_id)
        return admin_session

    def admin_validate_session(self, admin_session_id):
        self.log.debug("BEGIN admin_validate_session(admin_session_id=%s)", admin_session_id)

        dbs = DBSession()

        admin_session = self.admin_get_session(dbs, admin_session_id)
        if admin_session is None:
            self.log.warn("admin_validate_session(admin_session_id=%s): Invalid session", admin_session_id)
            raise Exception("Invalid session")

        admin_session.updated = datetime.now()

        try:
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.debug("END admin_validate_session(admin_session_id=%s)", admin_session_id)
        return admin_session.user.data()

    def admin_kill_session(self, admin_session_id):
        self.log.debug("BEGIN admin_kill_session(admin_session_id=%s)", admin_session_id)

        dbs = DBSession()

        admin_session = self.admin_get_session(dbs, admin_session_id)
        if admin_session is None:
            self.log.warn("admin_kill_session(admin_session_id=%s): Invalid session", admin_session_id)
            raise Exception("Invalid session")

        try:
            dbs.delete(admin_session)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.debug("END admin_kill_session(admin_session_id=%s)", admin_session_id)
        return True

    def admin_certificate_login(self):
        pass  # TODO

    def admin_get_certificate(self, admin_session_id, certificate_id):
        self.log.debug("BEGIN admin_get_certificate(admin_session_id=%s, certificate_id=%s)", admin_session_id,
                       certificate_id)

        dbs = DBSession()

        admin_session = self.admin_get_session(dbs, admin_session_id)
        if admin_session is None:
            self.log.warn("admin_get_certificate(admin_session_id=%s, certificate_id=%s): Invalid session",
                          admin_session_id, certificate_id)
            raise Exception("Invalid session")

        certificate = dbs.query(Certificate).filter_by(Certificate.id == certificate_id).fetch_one()
        if certificate is None:
            raise Exception("Invalid certificate")  # TODO: Better exception

        self.log.debug("END admin_get_certificate(admin_session_id=%s, certificate_id=%s)", admin_session_id,
                       certificate_id)
        return certificate.data()

    def admin_get_certificates(self, admin_session_id):
        self.log.debug("BEGIN admin_get_certificates(admin_session_id=%s)", admin_session_id)

        dbs = DBSession()

        admin_session = self.admin_get_session(dbs, admin_session_id)
        if admin_session is None:
            self.log.warn("admin_get_certificates(admin_session_id=%s): Invalid session", admin_session_id)
            raise Exception("Invalid session")

        certificates = dbs.query(Certificate).all()

        self.log.debug("END admin_get_certificates(admin_session_id=%s)", admin_session_id)
        return [certificate.data() for certificate in certificates]

    def admin_get_update_requests(self, admin_session_id):
        self.log.debug("BEGIN admin_get_update_requests(admin_session_id=%s)", admin_session_id)

        dbs = DBSession()

        admin_session = self.admin_get_session(dbs, admin_session_id)
        if admin_session is None:
            self.log.warn("admin_get_update_requests(admin_session_id=%s): Invalid session", admin_session_id)
            raise Exception("Invalid session")

        update_requests = dbs.query(UpdateRequest).all()

        self.log.debug("END admin_get_update_requests(admin_session_id=%s)", admin_session_id)
        return [update_request.data() for update_request in update_requests]

    def admin_reject_update_request(self, admin_session_id, update_request_id):
        self.log.debug("BEGIN admin_reject_update_requests(admin_session_id=%s, update_request_id=%s)",
                       admin_session_id, update_request_id)

        dbs = DBSession()

        admin_session = self.admin_get_session(dbs, admin_session_id)
        if admin_session is None:
            self.log.warn("admin_reject_update_requests(admin_session_id=%s, update_request_id=%s): Invalid session",
                          admin_session_id, update_request_id)
            raise Exception("Invalid session")

        update_request = dbs.query(UpdateRequest).filter_by(UpdateRequest.id == update_request_id).fetch_one()
        if update_request is None:
            self.log.warn(
                "admin_reject_update_requests(admin_session_id=%s, update_request_id=%s): Invalid update request",
                admin_session_id, update_request_id)
            raise Exception("Invalid update request")

        try:
            dbs.delete(update_request)
            dbs.commit()
        except:
            dbs.rollback()
            # TODO: Inform the caller that something bad happened

        self.log.debug("END admin_reject_update_requests(admin_session_id=%s, update_request_id=%s)",
                       admin_session_id, update_request_id)
        return True

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