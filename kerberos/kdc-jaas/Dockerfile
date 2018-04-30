FROM maven:3.5.3-jdk-8

ENV KDC_MASTER_PWD abc1234
ENV KDC_REALM CRYPTO.ORG

ENV ADMIN_PWD abc1234


RUN apt-get update && \
    apt-get install -y wget tar vim less net-tools iputils-ping

#COPY ./conf/kdc.conf /etc/kdc.conf
#COPY ./conf/krb5.conf /etc/krb5.conf
#COPY ./conf/kadm5.acl /etc/kadm5.acl


ENTRYPOINT ["bash"]
