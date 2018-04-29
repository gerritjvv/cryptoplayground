FROM ubuntu:16.04

ENV KDC_MASTER_PWD abc1234
ENV KDC_REALM CRYPTO.ORG

ENV ADMIN_PWD abc1234

COPY src/krb5-1.16/ /opt/krb5-1.16

RUN apt-get update && \
    apt-get install -y build-essential checkinstall wget tar byacc flex vim less && \
    mkdir -p /opt/ && \
    echo cd /opt/ && wget http://web.mit.edu/KERBEROS/dist/krb5/1.16/krb5-1.16.tar.gz && \
    echo tar -xzf ./krb5-1.16.tar.gz && \    
    cd /opt/krb5-1.16/src && \
    ./configure && \
    make && \
    make install && \
    make check && \
    cd / && \
    apt-get remove -y build-essential checkinstall && \
    rm -rf /opt/krb5-1.16 && \
    rm -rf /opt/krb*.tar.gz && \
    mkdir -p /usr/local/var/krb5kdc

RUN apt-get install -y lsof net-tools iputils-ping rsyslog 
COPY ./conf/kdc.conf /etc/kdc.conf
COPY ./conf/krb5.conf /etc/krb5.conf
COPY ./conf/kadm5.acl /etc/kadm5.acl

COPY ./entrypoint.sh /opt/entrypoint.sh

RUN kdb5_util create -r $KDC_REALM -s -P $KDC_MASTER_PWD
RUN kadmin.local addprinc -pw $ADMIN_PWD root/admin@CRYPTO.ORG && \
    kadmin.local addprinc -pw $ADMIN_PWD admin/admin@CRYPTO.ORG && \
    kadmin.local addprinc -pw $ADMIN_PWD admin/kdc.crypto.org@CRYPTO.ORG && \
    kadmin.local addprinc -pw $ADMIN_PWD kadmin/kdc.crypto.org@CRYPTO.ORG && \
    kadmin.local addprinc -pw dev1234 root/dev@CRYPTO.ORG && \
    kadmin.local listprincs 
    
RUN touch /var/log/krb5kdc.log && \
    chmod -R 777 /var/log/krb5kdc.log

EXPOSE 88
EXPOSE 749
EXPOSE 464
EXPOSE 754

ENTRYPOINT /opt/entrypoint.sh
