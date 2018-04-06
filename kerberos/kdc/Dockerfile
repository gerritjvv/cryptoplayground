FROM ubuntu:16.04

ENV KDC_MASTER_PWD abc1234
ENV KDC_REALM CRYPTO.ORG

ENV ADMIN_PWD abc1234

RUN apt-get update && \
    apt-get install -y build-essential checkinstall wget tar byacc flex && \
    mkdir -p /opt/ && \
    cd /opt/ && wget http://web.mit.edu/KERBEROS/dist/krb5/1.16/krb5-1.16.tar.gz && \
    tar -xzf ./krb5-1.16.tar.gz && \
    cd /opt/krb5-1.16/src && \
    ./configure && \
    make && \
    make install && \
    make check && \
    cd / && \
    apt-get remove -y build-essential checkinstall && \
    rm -rf /opt/krb5-1.16 && \
    rm -rf /opt/krb*.tar.gz

ADD ./conf/kdc.conf /etc/kdc.conf
ADD ./conf/krb5.conf /etc/krb5.conf
ADD ./conf/kadm5.acl /usr/local/var/krb5kdc/kadm5.acl
COPY ./entrypoint.sh /opt/entrypoint.sh

RUN kdb5_util create -r $KDC_REALM -s -P $KDC_MASTER_PWD && \
    kadmin.local addprinc -pw $ADMIN_PWD admin/admin@CRYPTO.ORG && \
    kadmin.local addprinc -pw $ADMIN_PWD test/admin@CRYPTO.ORG && \
    kadmin.local listprincs 


EXPOSE 88
EXPOSE 749
EXPOSE 464
EXPOSE 754

ENTRYPOINT /opt/entrypoint.sh
