# Kerberos KDC Playground


## Overview


Kerberos requires correct DNS setup and configuration, for this reason everything from the client to the KDC should run inside
the docker-compose environment.

The docker-compose specifies 2 main services:

* kdc.crypto.org => Kerberos Key distribution centre (KDC)
* dev.crypto.org => dev machine to connect to the KDC

A helper script build.sh is provided to automate running docker-compose commands for each usecase.

### Build.sh Commands

* start/stop, start stop the docker-compose instances
* kdcbash, log into the kdc instance
* devbash, log into the dev instance
* build/devbuild, build the docker instances
* userpwdlogin, run the user pwd login example in kdc-jaas/kdc-userpwd-login.sh
* keytablogin, run the keytab login example in kdc-jaas/kdc-keytab-login.sh


## Getting started

From the command line run: ```./build.sh build```, this might take a while.
Then run ```./build.sh start```


## Add and List KDC Principals (like adding users)

Form the command line run:
```./build kdcbash```

To see the existing principals run:
```kadmin.local listprincs```

Then add a principal:
```kamdin.local addprinc testuser/dev@crypto.org```

To extract a keytab (for passwordless auth) run:
```kadmin.local ktadd -k /var/tabs/mydev.keytab testuser/dev@CRYPTO.ORG```

## Run the kdc-jaas examples

```./build.sh userpwdlogin testuser/dev@CRYPTO.ORG```

```./build.sh keytablogin root/dev@CRYPTO.ORG```

The userpwd login uses:

```
kerberosUserPwdLogin {
  com.sun.security.auth.module.Krb5LoginModule required debug=true doNotPrompt=false;
};
```

The keytab login uses:

```
kerberosKeytabLogin {
  com.sun.security.auth.module.Krb5LoginModule required doNotPrompt=true debug=true useKeyTab=true keyTab="/var/tabs/dev.keytab";
};
```


# Exmaples

![KDCJAASEXample](https://github.com/gerritjvv/cryptoplayground/blob/master/kerberos/docs/kdcstartloginexample.gif)
