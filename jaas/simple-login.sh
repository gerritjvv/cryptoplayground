#!/usr/bin/env bash


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$DIR"
mvn install

java -cp "$DIR/target/jaas-1.0-SNAPSHOT.jar" \
     -Djava.security.auth.login.config="$DIR/src/resources/simplelogin.jaas" \
     org.cryptopg.jaas.SimpleLogin $@
