# AppliedLab

Repository for http://www.infsec.ethz.ch/education/as2013/appliedlab

## Servers
### Firewall
* Some linux shit
* OpenVPN

### Web server
* Debian
* Iptables
* Nginx
* Python
* Flask
* ZeroRPC
* SSH access for connections from firewall

### CACore/Database
* Debian
* Iptables
* Python
* ZeroRPC
* OpenSSL
* MySQL
* SSH access for connections from firewall

### Archive/Backup
* Debian
* Iptables
* SSH access for connections from firewall and CACore
* Syslog server

## Web server
* Only accessible via HTTPS
* Identifies each visitor with a session cookie or something like that
* 

## CACore API
### User management
#### credential_login(username, password)
* Check legacy db for valid username/password combination
* Returns a session id and user data on success, raises exception otherwise

#### validate_session(session_id)
* Validate the session id
* Returns True on success, raises exception otherwise

#### kill_session(session_id)
* Kills the session
* Returns True

#### cert_login(...)
* How does this work?
* Returns a session id and user data on success, raises Exception otherwise

#### change_data(session_id, new_data)
* Changes the users data
* Revokes all certificates for the current user
* Returns user data on success, raises exception otherwise

### Certificate 
#### getCRL()
* Returns the CRL

#### create(session_id)
* Create a new public/private keypair and sign it with the CA key
* Returns public and private keys and the signed certificate

#### revoke(session_id, cert)
* Revokes the certificate if it belongs to the user that coresponds to the session_id
* Returns True on success, raises exception otherwise

### Admin
#### certLogin(...)
* Same as user certLogin, but only for CA administrators
* Returns an admin_session_id on success, raises exception otherwise

#### getStatus(admin_session_id)
* Returns the current status of the CA (# issued certs, current serial number, ...)

## Backup stuff
* LOL DUNNO HAHAHAHAHAHAHAHAHAA

## Logging
* Syslog server

