package org.cryptopg.jaas;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Set;

/**
 * Demonstrates a simple JAAS login user a hardcoded username and password.
 * The objective is to use the simplest form to demonstrate how JAAS works.
 * <p>
 * https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/tutorials/GeneralAcnOnly.html
 */
public class SimpleLogin {
    public static void main(String[] args) throws LoginException {

        if (args.length != 2) {
            System.err.println("<command> userName password");
            System.exit(-1);
        }

        String userName = args[0];
        char[] pwd = args[1].toCharArray();

        LoginContext ctx = new LoginContext("simplelogin", userPasswordCallback(userName, pwd));

        try {
            //if the module returns false for login a LoginException is thrown
            ctx.login();
            Subject subject = ctx.getSubject();

            //not that principals might not be set for what ever reason
            //in this case the set is empty.
            //some applications might decide to ignore principals and just accept user login.
            Set<Principal> principalSet = subject.getPrincipals();

            if(principalSet.isEmpty()) {
                throw new LoginException("No identities (principals) were assigned to this user");
            }

            System.out.println("Logged in: " + principalSet.iterator().next().getName());
        } catch(LoginException loge) {
            System.out.println("Failed to login please user user=test, password=password; msg = " + loge.getMessage());
        }

    }

    private static final CallbackHandler userPasswordCallback(String userName, char[] password) {
        char[] pwdCopy = Arrays.copyOf(password, password.length);

        return (Callback[] callbacks) -> {
            for (Callback c : callbacks) {
                if (c instanceof PasswordCallback) {
                    //here we set the password to the password callback
                    ((PasswordCallback) c).setPassword(pwdCopy);
                } else if (c instanceof TextInputCallback) {
                    //here we set the user name to the text input callback
                    ((TextInputCallback) c).setText(userName);
                }
            }
        };
    }


}
