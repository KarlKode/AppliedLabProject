class InternalError(Exception):
    def __init__(self, message, session_id='Unknown', user_id='Unknown'):
        super(InternalError, self).__init__(message)
        self.session_id = session_id
        self.user_id = user_id


class InvalidSessionError(Exception):
    def __init__(self, message, session_id):
        super(InvalidSessionError, self).__init__(message)
        self.session_id = session_id


class InvalidCredentialsError(Exception):
    def __init__(self, message, user_id, session_id='-'):
        super(InvalidCredentialsError, self).__init__(message)
        self.user_id = user_id
        self.session_id = session_id


class InvalidCertificateError(Exception):
    def __init__(self, message, session_id, user_id, certificate_id, certificate=""):
        super(InvalidCertificateError, self).__init__(message)
        self.certificate_id = certificate_id
        self.certificate = certificate
        self.session_id = session_id
        self.user_id = user_id


class CertificateCreationError(Exception):
    def __init__(self, message, session_id, user_id):
        super(CertificateCreationError, self).__init__(message)
        self.user_id = user_id
        self.session_id = session_id
