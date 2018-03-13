package org.cryptopg.jaas;

import com.sun.security.auth.UserPrincipal;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

public class SimpleLoginModule implements LoginModule {

    private Subject subject;
    private CallbackHandler callbackHandler;

    private final String testUserName = "test";
    private final char[] testPassword = "password".toCharArray();

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
    }

    @Override
    public boolean login() throws LoginException {

        // Create the Callbacks that will hold the data we request
        TextInputCallback userNameCB = new TextInputCallback("userid");
        PasswordCallback passwordCB = new PasswordCallback("password", false);

        try {

            //request data
            callbackHandler.handle(new Callback[]{userNameCB, passwordCB});


            //compare what the callback handler returns to our auth data
            boolean auth = testUserName.equals(userNameCB.getText()) &&
                    Arrays.equals(testPassword,
                            passwordCB.getPassword());

            if(auth) {
                subject.getPrincipals().add(new UserPrincipal("test/admin"));
            }

            return auth;


        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnsupportedCallbackException e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }
}
