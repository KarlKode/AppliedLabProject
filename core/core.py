import logging
import os
from threading import Lock
from M2Crypto import X509, EVP
import OpenSSL
import Pyro4
import time
from db import CoreDB

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
        self.db = None
        self.settings = {"DB": "/tmp/appseclab.db", "CHANGEABLE_USER_FIELDS": CHANGEABLE_USER_FIELDS}
        self.init_log()
        self.init_db()
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

    def init_db(self):
        self.log.info("Initializing CoreRPC database")
        self.db = CoreDB(self.settings)
        self.log.info("Initialized CoreRPC database")

    def credential_login(self, user_id, password):
        self.log.debug("BEGIN credential_login(user_id=%s, password=***)", user_id)

        user = self.db.get_user(user_id, password)
        if user is None:
            self.log.warn("credential_login(user_id=%s, password=***): Invalid credentials", user_id)
            raise Exception("invalid credentials")
        session_id = self.db.create_session(user["uid"])
        self.log.info("credential_login(user_id=%s, password=***): Login successful", user_id)

        self.log.debug("END credential_login(user_id=%s, password=***)", user_id)
        return session_id

    def validate_session(self, session_id):
        self.log.debug("BEGIN validate_session(session_id=%s)", session_id)

        session = self.db.get_session(session_id)
        if session is None:
            self.log.warn("validate_session(session_id=%s): Invalid session", session_id)
            raise Exception("Invalid session")
        user = self.db.get_user(session["uid"])
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

        self.db.delete_session(session_id)

        self.log.debug("END kill_session(session_id=%s)", session_id)
        return True

    def update_data(self, session_id, field, value_new):
        self.log.debug("BEGIN update_data(session_id=%s, field=%s, value_new=%s)", session_id, field, value_new)

        session = self.db.get_session(session_id)
        if session is None:
            self.log.error("update_data(session_id=%s, field=%s, value_new=%s): Invalid session", session_id, field,
                           value_new)
            raise Exception("Invalid session")
        user = self.db.get_user(session["uid"])
        if user is None:
            self.log.error("update_data(session_id=%s, field=%s, value_new=%s): Invalid user", session_id, field,
                           value_new)
            raise Exception("Invalid user")
        self.db.update_data(user["uid"], field, value_new)
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

        session = self.db.get_session(session_id)
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
    """
    def create_certificate_m2(self, session_id, title, description):

        session = self.db.get_session(session_id)
        if session is None:
            raise Exception("Invalid session")
        user = self.db.get_user(session["uid"])
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
        certificate.set_serial_number(self.db.get_serial_number())
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

        self.db.store_certificate(user["uid"], certificate_data, title, description)

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

def main():
    d = Pyro4.Daemon()
    ns = Pyro4.locateNS()  # Needs a NameServer running: python -m Pyro4.naming in shell
    uri = d.register(CoreRPC())
    ns.register("core", uri)
    d.requestLoop()


if __name__ == "__main__":
    main()