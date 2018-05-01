#!/usr/bin/env bash


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$DIR"
mvn install

echo "$DIR/target/kdc-jaas-1.0-SNAPSHOT.jar"
java -cp "$DIR/target/kdc-jaas-1.0-SNAPSHOT.jar" \
     -Dsun.security.krb5.debug=true \
     -Dsun.security.jgss.debug=true \
     -Djava.security.krb5.kdc=kdc.crypto.org \
     -Djava.security.krb5.realm=CRYPTO.ORG \
     -Djava.security.auth.login.config="$DIR/src/main/resources/kdc-login.jaas" \
     org.crypto.kdcjaas.KDCKeytabLogin $@
