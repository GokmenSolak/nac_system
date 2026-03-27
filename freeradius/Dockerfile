FROM freeradius/freeradius-server:latest

COPY mods-available/rest /etc/freeradius/mods-enabled/rest
COPY sites-available/default /etc/freeradius/sites-enabled/default

RUN chmod 640 /etc/freeradius/mods-enabled/rest /etc/freeradius/sites-enabled/default