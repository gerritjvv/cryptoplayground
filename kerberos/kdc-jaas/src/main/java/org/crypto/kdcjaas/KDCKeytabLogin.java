package org.crypto.kdcjaas;

import sun.security.krb5.Config;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.Arrays;

/**
 *
 * Shows how to do user
 *
 */
public class KDCKeytabLogin
{

    Config f;

    /**
     * For all properties see:
     * The un.security.krb5.Config class
     * @param args
     * @throws LoginException
     */
    public static void main( String[] args ) throws LoginException {

        String principal = args.length == 1 ? args[0] : "root/dev@CRYPTO.ORG";

        System.setProperty("sun.security.krb5.principal", principal.trim());

        checkPropertiesConfigured();

        System.out.println("Login using: " + principal);

        LoginContext loginContext = new LoginContext("kerberosKeytabLogin", (Callback[] callbacks) -> {
            throw new RuntimeException("Keytab could not be found");
        });

        try{
            loginContext.login();

            Subject subject = loginContext.getSubject();

            printSubjectInfo(subject);

        } catch(LoginException excp) {
            System.out.println("Failed to login " + excp.getMessage());
        }
    }

    private static void checkPropertiesConfigured() {

        String kdc = System.getProperty("java.security.krb5.kdc");
        if(kdc == null || kdc.length() < 1)
            throw new RuntimeException("-Djava.security.krb5.kdc= must be defined");

        String realm = System.getProperty("java.security.krb5.realm");
        if(realm == null || realm.length() < 1)
            throw new RuntimeException("-Djava.security.krb5.realm= must be defined");

        String loginConfig = System.getProperty("java.security.auth.login.config");

        // we force a jaas configuration here, but kerberos settings can also be loaded from /etc/krb5.conf
        if(loginConfig == null || loginConfig.length() < 1)
            throw new RuntimeException("-Djava.security.auth.login.config  must be defined");


    }

    private static void printSubjectInfo(Subject subject) {
        System.out.println("Logged in");

        System.out.println("----------------------------------------------------------------------");
        System.out.println(subject);
        System.out.println("----------------------------------------------------------------------");

        System.out.println("Principals");

        for(Principal p : subject.getPrincipals()) {
            System.out.println(p.getClass());
            System.out.println(p.getName());

            if(p instanceof KerberosPrincipal) {
                KerberosPrincipal kerbp = (KerberosPrincipal)p;

                System.out.println("\trealm: " + kerbp.getRealm());
            }
        }

        System.out.println("Public Credentials");

        for (Object cred :subject.getPublicCredentials()) {
            System.out.println(cred);
        }


        System.out.println("Private Credentials");

        for (Object cred :subject.getPublicCredentials()) {
            System.out.println(cred);
        }
    }
}
