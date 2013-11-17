import logging
import os
from threading import Lock
from M2Crypto import X509, EVP
from M2Crypto.X509 import X509Error
import OpenSSL
import Pyro4
from datetime import datetime
from functools import wraps
import base64
from sqlalchemy.orm.exc import NoResultFound
from db import DBSession
from errors import *
from models import User, Session, UpdateRequest, hash_pwd, Certificate, AdminSession
import settings


def expose(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        self = args[0]
        arguments = ", ".join([str(arg) for arg in args[1:]])
        self.log.debug("BEGIN %s(%s)", f.__name__, arguments)
        try:
            r = {"_rpc_status": "success", "data": f(*args, **kwargs)}
        except InvalidSessionError:
            self.log.warn("Invalid session")
            r = {"_rpc_status": "error", "error": "Invalid session"}
        except InvalidCredentialsError:
            self.log.warn("Invalid credentials")
            r = {"_rpc_status": "error", "error": "Invalid credentials"}
        except InternalError:
            self.log.error("Internal error")
            r = {"_rpc_status": "error", "error": "Internal error"}
        except InvalidCertificateError:
            self.log.error("Invalid certificate")
            r = {"_rpc_status": "error", "error": "Internal certificate"}
        except Exception as e:
            self.log.error("Unknown exception: %r" % (e,))
            r = {"_rpc_status": "error", "error": "Internal error"}
            raise
        self.log.debug("END %s(%s)", f.__name__, arguments)
        return r

    return decorated_function


class CoreRPC(object):
    def __init__(self):
        self.log = None
        self.init_log()
        self.lock = Lock()
        self.log.info("Initialized CoreRPC")

    def init_log(self):
        self.log = logging.getLogger("core")
        self.log.setLevel(logging.DEBUG)
        self.log.addHandler(logging.StreamHandler())
        self.log.info("Initialized CoreRPC logger")

    def _get_session(self, dbs, session_id):
        try:
            return dbs.query(Session).filter(Session.id == session_id).one()
        except NoResultFound:
            raise InvalidSessionError

    def _revoke_certificate(self, dbs, certificate):
        if certificate.revoked:
            raise InvalidCertificateError("Certificate already revoked")

        certificate_instance = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate.certificate)

        # TODO: Hacky shit. PLZ FIX ME!!!!!
        ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                file(os.path.join(
                                                    settings.PKI_DIRECTORY, settings.KEY_FILENAME), "rb").read())
        ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                  file(os.path.join(
                                                      settings.PKI_DIRECTORY, settings.CERT_FILENAME), "rb").read())

        # This optional field describes the version of the encoded CRL.  When
        # extensions are used, as required by this profile, this field MUST be
        # present and MUST specify version 2 (the integer value is 1).
        revoked = OpenSSL.crypto.Revoked()
        revoked.set_reason(None)  # TODO: Change this
        revoked.set_rev_date(datetime.now().strftime("%Y%m%d%H%M%SZ"))
        revoked.set_serial("%x" % (certificate_instance.get_serial_number(),))

        with self.lock:
            try:
                if os.path.isfile(os.path.join(settings.PKI_DIRECTORY, settings.CRL_FILENAME)):
                    crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM,
                                                  file(os.path.join(
                                                      settings.PKI_DIRECTORY, settings.CRL_FILENAME), "rb").read())
                else:
                    crl = OpenSSL.crypto.CRL()

                crl.add_revoked(revoked)
                file(os.path.join(
                    settings.PKI_DIRECTORY, settings.CRL_FILENAME), "wb").write(crl.export(ca_cert, ca_key))
            except Exception as e:
                raise

        certificate.revoked = True
        try:
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Database error")
        return True

    @expose
    def validate_session(self, session_id):
        dbs = DBSession()
        session = self._get_session(dbs, session_id)
        session.updated = datetime.now()
        try:
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Could not update the session's timestamp")
        return session.user.data()

    @expose
    def kill_session(self, session_id):
        dbs = DBSession()

        session = self._get_session(dbs, session_id)
        try:
            dbs.delete(session)
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Database error")
        return True

    @expose
    def credential_login(self, user_id, password):
        dbs = DBSession()
        try:
            user = dbs.query(User).filter(User.uid == user_id, User.pwd == hash_pwd(password)).one()
        except NoResultFound:
            raise InvalidCredentialsError

        # Create a new session for the user
        session = Session(user.uid)
        try:
            dbs.add(session)
            dbs.commit()
        except Exception as e:
            dbs.rollback()
            raise InternalError("Database error: " + str(e))

        return session.id

    @expose
    def certificate_login(self, certificate):
        pass  # TODO

    @expose
    def update_data(self, session_id, field, value_new):
        dbs = DBSession()

        session = self._get_session(dbs, session_id)
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
            raise InternalError("Invalid field")

        update_request = UpdateRequest(session.user.uid, field, value_old, value_new)
        try:
            dbs.add(update_request)
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Database error")
        return True

    @expose
    def get_crl(self):
        with self.lock:
            if os.path.isfile(os.path.join(settings.PKI_DIRECTORY, settings.CRL_FILENAME)):
                crl = file(os.path.join(settings.PKI_DIRECTORY, settings.CRL_FILENAME), "rb").read()
            else:
                crl = ""
        return crl

    @expose
    def get_certificate(self, session_id, certificate_id):
        dbs = DBSession()
        session = self._get_session(dbs, session_id)
        try:
            return session.user.certificates.filter(
                Certificate.id == certificate_id,
                Certificate.revoked == False
            ).one().data()
        except NoResultFound:
            raise InvalidCertificateError("Invalid certificate")

    @expose
    def get_certificates(self, session_id):
        dbs = DBSession()
        session = self._get_session(dbs, session_id)
        try:
            # Get the data dictionary for every certificate of the user
            return [certificate.data() for certificate in
                    session.user.certificates.filter(Certificate.revoked == False).all()]
        except NoResultFound as e:
            print e.message
            print e
            raise InternalError("Database error")

    @expose
    def create_certificate(self, session_id, title, description):
        dbs = DBSession()
        session = self._get_session(dbs, session_id)

        # Generate a new key
        k = OpenSSL.crypto.PKey()
        k.generate_key(OpenSSL.crypto.TYPE_RSA, settings.RSA_BITS)

        certificate = OpenSSL.crypto.X509()
        subject = certificate.get_subject()  # TODO: We should change this
        subject.countryName = "CH"
        subject.stateOrProvinceName = "Zurich"
        subject.localityName = "Zurich"
        subject.organizationName = "iMovies"
        subject.organizationalUnitName = "Users"
        subject.commonName = "%s %s %s" % (session.user.firstname, session.user.uid, session.user.lastname)
        subject.emailAddress = session.user.email

        try:
            serial_number = dbs.query(Certificate).count() + 1
        except:
            raise CertificateCreationError()

        certificate.set_pubkey(k)
        certificate.set_serial_number(serial_number)
        certificate.gmtime_adj_notBefore(0)  # Now
        certificate.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 365 days

        # TODO: Change crl url
        extensions = [OpenSSL.crypto.X509Extension("crlDistributionPoints", True, "URI:http://example.com/crl.pem")]
        certificate.add_extensions(extensions)

        # TODO: Hacky shit. PLZ FIX ME!!!!!
        ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                file(os.path.join(
                                                    settings.PKI_DIRECTORY, settings.KEY_FILENAME), "rb").read())
        ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                  file(os.path.join(
                                                      settings.PKI_DIRECTORY, settings.CERT_FILENAME), "rb").read())

        # Set certificate issuer and sign the certificate
        certificate.set_issuer(ca_cert.get_subject())
        certificate.sign(ca_key, "sha1")

        # Get the actual certificate
        certificate_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
        certificate_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k)
        certificate_pkcs12 = OpenSSL.crypto.PKCS12()
        #certificate_pkcs12.set_ca_certificates([ca_cert])
        certificate_pkcs12.set_certificate(certificate)
        certificate_pkcs12.set_privatekey(k)
        file("/home/m/a3_2.p12", "wb").write(certificate_pkcs12.export(""))

        db_certificate = Certificate(session.user.uid, title, description, certificate_pem)
        db_certificate.id = serial_number
        try:
            dbs.add(db_certificate)
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Database error")
        return {"certificate": certificate_pem,
                "key": certificate_key,
                "pkcs12": base64.b64encode(certificate_pkcs12.export(""))}  #Base64 encoded because of Pyro4

    # TODO: check if certificate is still valid (time) or if its on the revocation list
    @expose
    def verify_certificate(self, certificate):
        try:
            cert_object = X509.load_cert_string(str(certificate), X509.FORMAT_PEM)
            ca_key = EVP.load_key(os.path.join(settings.PKI_DIRECTORY, settings.KEY_FILENAME))
            verify_result = cert_object.verify(ca_key)
            if verify_result == 1:
                verify_result_text = "Valid"
                description = "The certificate is valid and was signed by the CA."
            else:
                verify_result_text = "Invalid"
                description = "The certificate is invalid. No more details are available."
        except X509Error:
            verify_result = 2
            verify_result_text = "Invalid"
            description = "The certificate is malformed."



        verification_data = {
            "status": verify_result,
            "status_text": verify_result_text,
            "description": description
        }
        return verification_data

    @expose
    def revoke_certificate(self, session_id, certificate_id):
        dbs = DBSession()
        session = self._get_session(dbs, session_id)
        try:
            certificate = session.user.certificates.filter(Certificate.id == certificate_id).one()
        except NoResultFound:
            raise InvalidCertificateError("Invalid certificate")
        return self._revoke_certificate(dbs, certificate)

    # ADMIN STUFF #

    def _admin_get_session(self, dbs, admin_session_id):
        try:
            return dbs.query(AdminSession).filter(AdminSession.id == admin_session_id).one()
        except NoResultFound:
            raise InvalidSessionError

    @expose
    def admin_validate_session(self, admin_session_id):
        dbs = DBSession()

        admin_session = self._admin_get_session(dbs, admin_session_id)
        admin_session.updated = datetime.now()
        try:
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Database error")
        return admin_session.user.data()

    @expose
    def admin_kill_session(self, admin_session_id):
        dbs = DBSession()
        admin_session = self._admin_get_session(dbs, admin_session_id)
        try:
            dbs.delete(admin_session)
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Database error")
        return True

    @expose
    def admin_certificate_login(self):
        pass  # TODO

    @expose
    def admin_get_certificate(self, admin_session_id, certificate_id):
        dbs = DBSession()
        self._admin_get_session(dbs, admin_session_id)
        try:
            return dbs.query(Certificate).filter(Certificate.id == certificate_id).one().data()
        except NoResultFound:
            raise InvalidCertificateError

    @expose
    def admin_get_certificates(self, admin_session_id):
        dbs = DBSession()
        admin_session = self._admin_get_session(dbs, admin_session_id)
        try:
            c = dbs.query(Certificate).all()
            certs = [certificate.data() for certificate in c]
            return certs
        except NoResultFound:
            raise InternalError("Database error")

    @expose
    def admin_get_update_requests(self, admin_session_id):
        dbs = DBSession()
        self._admin_get_session(dbs, admin_session_id)
        try:
            return [update_request.data() for update_request in dbs.query(UpdateRequest).all()]
        except NoResultFound:
            # TODO: This is most likely not correct
            raise InternalError("Database error")

    @expose
    def admin_reject_update_request(self, admin_session_id, update_request_id):
        dbs = DBSession()
        self._admin_get_session(dbs, admin_session_id)
        try:
            update_request = dbs.query(UpdateRequest).filter(UpdateRequest.id == update_request_id).one()
        except NoResultFound:
            # TODO
            raise Exception
        try:
            dbs.delete(update_request)
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Database error")
        return True

    @expose
    def admin_accept_update_request(self, admin_session_id, update_request_id):
        dbs = DBSession()
        self._admin_get_session(dbs, admin_session_id)
        try:
            update_request = dbs.query(UpdateRequest).filter(UpdateRequest.id == update_request_id).one()
            # We can not use update_request.user because SQLAlchemy does not support that because of the reference stuff
            user = dbs.query(UpdateRequest).filter(User.uid == update_request.uid).one()
            user.update({update_request.field:update_request.value_new})
        except NoResultFound:
            # TODO
            raise Exception
        try:
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Database error")
        return True

    @expose
    def admin_revoke_certificate(self, admin_session_id, certificate_id):
        dbs = DBSession()
        self._admin_get_session(dbs, admin_session_id)
        try:
            certificate = dbs.query(Certificate).filter(Certificate.id == certificate_id).one()
        except NoResultFound:
            raise InvalidCertificateError("Invalid certificate")
        return self._revoke_certificate(dbs, certificate)


def main():
    d = Pyro4.Daemon()
    ns = Pyro4.locateNS()  # Needs a NameServer running: python -m Pyro4.naming in shell
    uri = d.register(CoreRPC())
    ns.register("core", uri)
    d.requestLoop()

if __name__ == "__main__":
    main()