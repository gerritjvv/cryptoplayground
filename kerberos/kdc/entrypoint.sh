#!/usr/bin/env bash


export KRB5_CONFIG=/etc/krb5.conf
export KRB5_KDC_PROFILE=/etc/kdc.conf

mknod -m 640 /dev/xconsole c 1 3
chown syslog:adm /dev/xconsole

rsyslogd
krb5kdc

kadmin.local addprinc -pw dev1234 root/dev@CRYPTO.ORG
## export the dev keytab to a docker-compose shared volume, for use by dev.crypto.org
kadmin.local ktadd -k /var/tabs/dev.keytab root/dev@CRYPTO.ORG

kadmind -nofork
