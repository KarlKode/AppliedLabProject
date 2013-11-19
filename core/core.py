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
import serpent
from sqlalchemy.orm.exc import NoResultFound
from db import DBSession
from errors import *
from models import User, Session, UpdateRequest, hash_pwd, Certificate, AdminSession
import settings
from utils import encrypt

def expose(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        self = args[0]
        arguments = ", ".join([str(arg) for arg in args[1:]])
        self.log.debug("BEGIN %s(%s)", f.__name__, arguments)
        try:
            r = {"_rpc_status": "success", "data": f(*args, **kwargs)}
        except InvalidSessionError as e:
            self.log.warn("Invalid session")
            r = {"_rpc_status": "error", "error": "Invalid session", "obj": e.session_id}
        except InvalidCredentialsError as e:
            self.log.warn("Invalid credentials")
            r = {"_rpc_status": "error", "error": "Invalid credentials", "obj": e.user_id}
        except InternalError as e:
            self.log.error("Internal error")
            r = {"_rpc_status": "error", "error": "Internal error", "obj": ""}
        except InvalidCertificateError as e:
            self.log.error("Invalid certificate")
            r = {"_rpc_status": "error", "error": "Invalid certificate", "obj": e.certificate_id}
        except Exception as e:
            self.log.error("Unknown exception: %r" % (e,))
            r = {"_rpc_status": "error", "error": "Internal error", "obj": ""}
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
            raise InvalidSessionError("No valid session found!", session_id)

    def _revoke_certificate(self, dbs, certificate):
        if certificate.revoked:
            raise InvalidCertificateError("Certificate already revoked", certificate)

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

    def _verify_certificate(self, certificate):
        try:
            cert_object = X509.load_cert_string(str(certificate), X509.FORMAT_PEM)
            ca_key = EVP.load_key(os.path.join(settings.PKI_DIRECTORY, settings.KEY_FILENAME))
            verify_result = cert_object.verify(ca_key)

            if verify_result == 1:
                if cert_object.has_expired():
                    return {
                        "status": 4,
                        "status_text": "Invalid",
                        "description": "The certificate has expired"
                    }
                with self.lock:
                    try:
                        if os.path.isfile(os.path.join(settings.PKI_DIRECTORY, settings.CRL_FILENAME)):
                            crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM,
                                                          file(os.path.join(
                                                          settings.PKI_DIRECTORY, settings.CRL_FILENAME), "rb").read())
                            revoked = crl.get_revoked()

                            for revoked_cert in revoked:
                                if int(str(revoked_cert.get_serial()), 16) == cert_object.get_serial_number():
                                    return {
                                        "status": 3,
                                        "status_text": "Invalid",
                                        "description": "The certificate is revoked! Revocation date: %s."
                                                       % (revoked_cert.get_rev_date(),)
                                    }
                    except:
                        return {
                            "status": 0,
                            "status_text": "Invalid",
                            "description": "The certificate is invalid. No more details are available."
                        }
                return {
                    "status": 1,
                    "status_text": "Valid",
                    "description": "The certificate is valid and was signed by the CA.",
                    "subject": cert_object.get_subject()
                }
            else:
                return {
                    "status": 0,
                    "status_text": "Invalid",
                    "description": "The certificate is invalid. No more details are available."
                }
        except X509Error:
            return {
                "status": 2,
                "status_text": "Invalid",
                "description": "The certificate is malformed."
            }

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
            raise InvalidCredentialsError("Invalid credentials!", user_id, password)

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
        dbs = DBSession()

        result = self._verify_certificate(certificate)
        if result["status"] != 1:
            raise Exception("todo!")  # TODO
        user_id = result["subject"].commonName.split()[-2]
        try:
            user = dbs.query(User).filter(User.uid == user_id.lower()).one()
        except NoResultFound:
            raise InvalidCredentialsError("Invalid credentials!", user_id, None)

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
            raise InvalidCertificateError("Certificate not found", certificate_id)

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
        except Exception as e:
            raise CertificateCreationError("Error during creating certificate!", session.user.uid)

        certificate.set_pubkey(k)
        certificate.set_serial_number(serial_number)
        certificate.gmtime_adj_notBefore(0)  # Now
        certificate.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 365 days

        # TODO: Change crl url
        extensions = [OpenSSL.crypto.X509Extension("crlDistributionPoints", False, "URI:http://example.com/crl.pem")]
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

        try:
            backup_file = file(os.path.join(settings.BACKUP_OUTPUT_DIRECTORY, str(serial_number)), "wb")
            key_ct, ct, mac = encrypt(settings.BACKUP_PUBLIC_KEY, certificate_pkcs12.export(""))
            print "foo"
            backup_file.write(serpent.dumps({
                "key_ct": base64.b64encode(key_ct),
                "ct": base64.b64encode(ct),
                "mac": base64.b64encode(mac)
            }))
            print "bar"
        except Exception as e:
            print e
            print e.message
            raise InternalError("Could not write backup")

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
        return self._verify_certificate(certificate)

    @expose
    def revoke_certificate(self, session_id, certificate_id):
        dbs = DBSession()
        session = self._get_session(dbs, session_id)
        try:
            certificate = session.user.certificates.filter(Certificate.id == certificate_id).one()
        except NoResultFound:
            raise InvalidCertificateError("Invalid certificate", certificate_id)
        return self._revoke_certificate(dbs, certificate)

    # ADMIN STUFF #

    def _admin_get_session(self, dbs, admin_session_id):
        try:
            return dbs.query(AdminSession).filter(AdminSession.id == admin_session_id).one()
        except NoResultFound:
            raise InvalidSessionError("No valid session found!", admin_session_id)

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
            raise InvalidCertificateError("No Certificate found!", certificate_id)

    @expose
    def admin_get_certificates(self, admin_session_id):
        dbs = DBSession()
        admin_session = self._admin_get_session(dbs, admin_session_id)
        try:
            c = dbs.query(Certificate).all()
            certs = [certificate.data() for certificate in c]
            return certs
        except NoResultFound:
            raise InternalError("Database error, no certificates found")

    @expose
    def admin_get_update_requests(self, admin_session_id):
        dbs = DBSession()
        self._admin_get_session(dbs, admin_session_id)
        try:
            return [update_request.data() for update_request in dbs.query(UpdateRequest).all()]
        except NoResultFound:
            # TODO: This is most likely not correct
            raise InternalError("Database error, no update-request found")

    @expose
    def admin_reject_update_request(self, admin_session_id, update_request_id):
        dbs = DBSession()
        self._admin_get_session(dbs, admin_session_id)
        try:
            update_request = dbs.query(UpdateRequest).filter(UpdateRequest.id == update_request_id).one()
        except NoResultFound:
            raise InternalError("Database error, update with update_id: %s fails" % update_request_id)

        try:
            dbs.delete(update_request)
            dbs.commit()
        except:
            dbs.rollback()
            raise InternalError("Database error")
        return True


    @expose
    def admin_get_systeminformation(self, admin_session_id):
        dbs = DBSession();
        self._admin_get_session(dbs, admin_session_id)

        users_count = dbs.query(User).count()
        certificates_count = dbs.query(Certificate).count()

        active_certificates_count = dbs.query(Certificate).filter(Certificate.revoked == False).count()
        update_requests_count = dbs.query(UpdateRequest).count()

        data = {
            "users_count": users_count,
            "certificates_count": certificates_count,
            "active_certificates_count": active_certificates_count,
            "update_requests_count": update_requests_count
        }

        return data

    @expose
    def admin_accept_update_request(self, admin_session_id, update_request_id):
        dbs = DBSession()
        self._admin_get_session(dbs, admin_session_id)
        try:
            update_request = dbs.query(UpdateRequest).filter(UpdateRequest.id == update_request_id).one()
            # We can not use update_request.user because SQLAlchemy does not support that because of the reference stuff
            user = dbs.query(User).filter(User.uid == update_request.uid).one()
        except NoResultFound:
            raise InternalError("No user found with id %s" % update_request.uid)

        if update_request.field == "firstname":
            user.firstname = update_request.value_new
        elif update_request.field == "lastname":
            user.lastname = update_request.value_new
        elif update_request.field == "email":
            user.email = update_request.value_new
        else:
            raise InternalError("Field not found")

        try:
            certificates = dbs.query(Certificate).filter(Certificate.uid == update_request.uid, Certificate.revoked == False).all()
        except NoResultFound as e:
            raise InternalError("No active certificates found")

        for certificate in certificates:
            self._revoke_certificate(dbs, certificate)

        try:
            dbs.delete(update_request)
        except Exception as e:
            dbs.rollback()
            raise InternalError("Database error")

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
            raise InvalidCertificateError("No certificate found!", certificate_id)
        return self._revoke_certificate(dbs, certificate)


def main():
    core = CoreRPC()
    Pyro4.Daemon.serveSimple(
        {
            core: "core",
        },
        host="0.0.0.0",
        port=4444,
        ns=False
    )

if __name__ == "__main__":
    main()