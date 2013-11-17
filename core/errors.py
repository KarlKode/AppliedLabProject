class InternalError(Exception):
    pass


class InvalidSessionError(Exception):
    def __init__(self, message, session_id):
        super(InvalidSessionError, self).__init__(message)
        self.session_id = session_id


class InvalidCredentialsError(Exception):
    def __init__(self, message, user_id, password):
        super(InvalidCredentialsError, self).__init__(message)
        self.user_id = user_id
        self.password = password


class InvalidCertificateError(Exception):
    def __init__(self, message, certificate_id, certificate=""):
        super(InvalidCertificateError, self).__init__(message)
        self.certificate_id = certificate_id
        self.certificate = certificate


class CertificateCreationError(Exception):
    def __init__(self, message, user_id):
        super(CertificateCreationError, self).__init__(message)
        self.user_id = user_id
