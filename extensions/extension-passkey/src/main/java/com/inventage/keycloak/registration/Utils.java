package com.inventage.keycloak.registration;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.FormContext;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

class Utils {

    private static final String KEYS_USERDATA = "keyUserdata";
    private static final String KEYS_USERDATA_SEPARATOR = ";";
    private static final List<String> DEFAULT_KEYS_USERDATA = List.of(UserModel.FIRST_NAME, UserModel.LAST_NAME,
            UserModel.EMAIL, UserModel.USERNAME);

    private Utils() {
    }

    /**
     * We store the user data entered in the registration form in the session notes.
     * This information will later be retrieved to create a user account.
     */
    static void storeUserDataInAuthSessionNotes(FormContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel sessionModel = context.getAuthenticationSession();

        // We store each key
        String keys = Utils.serializeUserdataKeys(formData.keySet());
        sessionModel.setAuthNote(Utils.KEYS_USERDATA, keys);

        formData.forEach((key, value) -> {
            sessionModel.setAuthNote(key, formData.getFirst(key));
        });
    }

    static MultivaluedMap<String, String> getUserDataFromAuthSessionNotes(AuthenticationFlowContext context) {
        AuthenticationSessionModel sessionModel = context.getAuthenticationSession();
        List<String> keysUserdata = Utils
                .deserializeUserdataKeys(sessionModel.getAuthNote(Utils.KEYS_USERDATA));

        MultivaluedMap<String, String> userAttributes = new MultivaluedHashMap<>();
        if (keysUserdata != null) {
            for (String key : keysUserdata) {
                String value = sessionModel.getAuthNote(key);
                if (value != null) {
                    userAttributes.add(key, value);
                }
            }
        }
        return userAttributes;
    }

    /**
     * We retrieve the user data stored in the session notes and create a new user
     * in this realm, or update if it exists in context.
     */
    static void createOrUpdateUserFromAuthSessionNotes(AuthenticationFlowContext context) {
        createOrUpdateUserFromAuthSessionNotes(context, null);
    }

    static void createOrUpdateUserFromAuthSessionNotes(
            AuthenticationFlowContext context,
            String userId) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        MultivaluedMap<String, String> userAttributes = new MultivaluedHashMap<>();

        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        List<String> keysUserdata = Utils
                .deserializeUserdataKeys(authenticationSession.getAuthNote(Utils.KEYS_USERDATA));

        // keys userdata is transmitted from the UserCreationPasskeyAction class.
        if (keysUserdata != null) {
            for (String key : keysUserdata) {
                String value = authenticationSession.getAuthNote(key);
                if (value != null) {
                    userAttributes.add(key, value);
                }
            }
        } // In case that another custom FormAction than UserCreationPasskey is used.
        else {
            for (String key : DEFAULT_KEYS_USERDATA) {
                String value = authenticationSession.getAuthNote(key);
                if (value != null) {
                    userAttributes.add(key, value);
                }
            }
        }

        String email = formData.getFirst(UserModel.EMAIL);
        String username = formData.getFirst(UserModel.USERNAME);

        if (context.getRealm().isRegistrationEmailAsUsername()) {
            username = email;
        }

        context.getEvent().detail(Details.USERNAME, username)
                .detail(Details.REGISTER_METHOD, "form")
                .detail(Details.EMAIL, email);

        KeycloakSession session = context.getSession();
        UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
        UserModel user;

        if (userId != null) {
            // // Update existing user - ensure all required fields are present
            // if (!userAttributes.containsKey(UserModel.EMAIL)) {
            //     String email = formData.getFirst(UserModel.EMAIL);
            //     userAttributes.add(UserModel.EMAIL, email);
            // }
            // if (!userAttributes.containsKey(UserModel.FIRST_NAME)) {
            //     String firstName = formData.getFirst(UserModel.FIRST_NAME);
            //     userAttributes.add(UserModel.FIRST_NAME, firstName);
            // }
            // if (!userAttributes.containsKey(UserModel.LAST_NAME)) {
            //     String lastName = formData.getFirst(UserModel.LAST_NAME);
            //     userAttributes.add(UserModel.LAST_NAME, lastName);
            // }

            user = session.users().getUserById(context.getRealm(), userId);
            user.setEnabled(true);
            UserProfile profile = profileProvider.create(UserProfileContext.UPDATE_PROFILE, userAttributes, user);
            profile.update(false);
        } else {
            // Create new user
            UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION, userAttributes);
            user = profile.create();
            user.setEnabled(true);
            context.setUser(user);
        }

        context.getAuthenticationSession().setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, username);

        context.getEvent().user(user);
        context.getEvent().success();
        context.newEvent().event(EventType.LOGIN);
        context.getEvent().client(context.getAuthenticationSession().getClient().getClientId())
                .detail(Details.REDIRECT_URI, context.getAuthenticationSession().getRedirectUri())
                .detail(Details.AUTH_METHOD, context.getAuthenticationSession().getProtocol());
        String authType = context.getAuthenticationSession().getAuthNote(Details.AUTH_TYPE);
        if (authType != null) {
            context.getEvent().detail(Details.AUTH_TYPE, authType);
        }
    }

    /**
     * Creates a minimal user with temporary attributes to allow passkey
     * registration.
     * The user will be updated with complete information later.
     */
    static UserModel createMinimalUser(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);

        // Create minimal attributes required by Keycloak
        MultivaluedMap<String, String> minimalAttributes = new MultivaluedHashMap<>();
        String tempId = java.util.UUID.randomUUID().toString();
        String tempUsername = "temp_" + tempId;

        // Add all required attributes with temporary values
        minimalAttributes.add(UserModel.USERNAME, tempUsername);
        minimalAttributes.add(UserModel.FIRST_NAME, "Temporary");
        minimalAttributes.add(UserModel.LAST_NAME, "User");
        minimalAttributes.add(UserModel.EMAIL, tempUsername + "@temporary.com");

        // Create user profile and user
        UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION, minimalAttributes);
        UserModel user = profile.create();
        user.setEnabled(false); // Keep disabled until full registration

        // // Set user in context and return
        // context.setUser(user);
        return user;
    }

    private static String serializeUserdataKeys(Collection<String> keys, String separator) {
        final StringBuilder key = new StringBuilder();
        keys.forEach((s -> key.append(s + separator)));
        return key.toString();
    }

    private static String serializeUserdataKeys(Collection<String> keys) {
        return serializeUserdataKeys(keys, KEYS_USERDATA_SEPARATOR);
    }

    private static List<String> deserializeUserdataKeys(String key, String separator) {
        if (key == null) {
            return Collections.emptyList();
        }
        return List.of(key.split(separator));
    }

    private static List<String> deserializeUserdataKeys(String key) {
        return deserializeUserdataKeys(key, KEYS_USERDATA_SEPARATOR);
    }
}
