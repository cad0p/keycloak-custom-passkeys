package com.inventage.keycloak.registration;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * This class contains all the logic when the
 * passkey-registration.ftl file is rendered or interacted with.
 * passkey-registration.ftl displays a page with a button labeled
 * with setup with passkey.
 * <p>
 * This authenticator is supposed to be used in the registration flow.
 * Purpose: Determine if the user wants to set up a passkey or password for
 * their user account.
 * <p>
 * IMPORTANT: This authenticator can only be used when
 * {@link RegistrationUserCreationNoAccount} is used in the registration form,
 * as we rely on data submitted in the session authentication notes in
 * UserCreationPasskeyAction.
 */
public class PasskeyRegistrationAuthenticator implements Authenticator {

    public static final String SETUP_TYPE = "setupType";
    public static final String SETUP_PASSKEY = "passkey";
    private static final String TPL_CODE = "passkey-registration.ftl";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form();
        // Render passkey-registration.ftl form to user
        context.challenge(form.createForm(TPL_CODE));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();

        // The setup type (whether the user wants to set up a passkey or a password) is
        // passed via form parameter
        String setupType = params.getFirst(SETUP_TYPE);

        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        if (setupType.equals(SETUP_PASSKEY)) {
            // We create an user from the session notes. The existence of this user is
            // required in WebAuthnPasswordlessRegister.
            Utils.createUserFromAuthSessionNotes(context);
            if (!authenticationSession.getRequiredActions().contains(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID)) {
                // We add the WebAuthnPasswordlessRegister as required action (for registering
                // passkeys) if not already configured in keycloak.
                authenticationSession.addRequiredAction(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID);
            }
            context.success();
        } else {
            // If the user chooses another setup type (password). We continue with the
            // alternative configured in the registration flow.
            context.attempted();
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
