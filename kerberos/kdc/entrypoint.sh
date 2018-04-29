#!/usr/bin/env bash


export KRB5_CONFIG=/etc/krb5.conf
export KRB5_KDC_PROFILE=/etc/kdc.conf

mknod -m 640 /dev/xconsole c 1 3
chown syslog:adm /dev/xconsole

rsyslogd
krb5kdc
kadmind -nofork
