# Host #
* cd core/pki
* ./create_ca.sh
* cp ca.crt ../../files/ca.crt
* cp ca.key ../../files/ca.key
* TODO: Create certificate for web server

# CoreCA #
* mkdir ~/host
* mount -t vboxsf lab host
* cp -R ~/host/core ~/
* connect to NAT and disable firewall with firestarter
* sudo apt-get install python-openssl python-m2crypto python-sqlalchemy python-mysqldb
* sudo pip install Pyro4
* edit mysql settings in core/settings.py
* cp ~/host/files/ca.key ~/core/pki/ca.key
* cp ~/host/files/ca.crt ~/core/pki/ca.crt
* cd ~/core/ && python core.py

# Webserver #
* mkdir ~/host
* mount -t vboxsf lab host
* connect to NAT and disable firewall with firestarter
* sudo apt-get install nginx-extras
* sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
* sudo cp ~/host/files/nginx.conf /etc/nginx/nginx.conf
* sudo cp ~/host/files/imovies.crt /etc/nginx/imovies.crt
* sudo cp ~/host/files/imovies.key /etc/nginx/imovies.key
* sudo cp ~/host/files/ca.crt /etc/nginx/ca.crt
* sudo mkdir /var/www
* sudo cp -R  ~/host/web /var/www/
* sudo chown -R www-data:www-data /var/www
* sudo invoke-rc.d nginx restart
* sudo apt-get install uwsgi-core uwsgi-plugin-python
* sudo cp ~/host/files/web.ini /etc/uwsgi/apps-available/web.ini
* sudo ln -s /etc/uwsgi/apps-available/web.ini /etc/uwsgi/apps-enabled/web.ini
* pip install Pyro4 flask-wtf
* sudo invoke-rc.d uwsgi restart

