

stash_file:
  
The stash file is a local copy of the master key that resides in encrypted form on the KDC’s local disk. The stash file is used to authenticate the KDC to itself automatically before starting the kadmind and krb5kdc daemons (e.g., as part of the machine’s boot sequence)

keytab file
All Kerberos server machines need a keytab file to authenticate to the KDC. By default on UNIX-like systems this file is named DEFKTNAME. The keytab file is an local copy of the host’s key

/etc/krb5.keytab

kadmin ktadd  host/trillium.mit.edu ftp/trillium.mit.edu


application server

An application server is a host that provides one or more services over the network


CREATE KDC DB and stash file

The docker instance is installed by default with a db "abc1234"

1. kdb5_util create -r CRYPTO.ORG -s or kdb5_util create -r CRYPTO.ORG -s -P abc1234

2. add the administrator principal (in the example root) to the kadm5.conf

/usr/local/var/krb5kdc/kadm5.acl
*/root@CRYPTO.ORG  l *  

see: https://web.mit.edu/kerberos/krb5-1.15/doc/admin/conf_files/kadm5_acl.html#kadm5-acl-5


2. add admin principal to kerberos database
    kadmin.local addprinc -pw $ADMIN_PWD admin/admin@CRYPTO.ORG && \

this allows the kadmin client to talk to the kadmin daemon over the network


3. startup

krb5kdc
kadmin


