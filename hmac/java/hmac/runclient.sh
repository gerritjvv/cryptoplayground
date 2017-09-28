#!/usr/bin/env bash

mvn clean install -DskipTests=true && mvn exec:java -Dexec.mainClass="org.funsec.hmac.TOTPApp" -Dexec.args="-client"

