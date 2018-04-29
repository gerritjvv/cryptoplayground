#~/usr/bin/env bash

dir=$(cd -P -- "$(dirname -- "$)")" && pwd -P)

build() {
 docker-compose build
}

devbuild() {
 docker-compose build dev.crypto.org
}

info() {
 docker-compose ps
}

start() {
 docker-compose up -d
 info 
}

stop() {
 docker-compose down
}

kdcbash() {
 docker-compose exec kdc.crypto.org bash
}

devbash() {
 docker-compose run dev.crypto.org $@
}

user_pwd_login() {
 mvn package
 devbash /root/dev/kdc-jaas/kdc-userpwd-login.sh $@
}


CMD="$1"

case $CMD in
	devbuild)
		devbuild
		;;
	build) 
		build
		;;
	kdcbash)
		kdcbash
		;;
	devbash)
		devbash
		;;
	userpwdlogin)
	    shift
	    user_pwd_login $@
	    ;;
	info)
		info
		;;
	start)
		start
		;;
	stop)
		stop
		;;
	*)
		echo "Please type start|stop|kdcbash|devbash|build|devbuild|info"
		;;
esac 
