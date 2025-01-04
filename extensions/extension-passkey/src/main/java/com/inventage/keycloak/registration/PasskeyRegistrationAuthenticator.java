package com.inventage.keycloak.registration;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.Algorithm;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.Challenge;

import com.webauthn4j.data.client.challenge.DefaultChallenge;

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

        MultivaluedMap<String, String> userAttributes = Utils.getUserDataFromAuthSessionNotes(context);
        // Use standard UTF-8 charset to get bytes from string.
        // Otherwise the platform's default charset is used and it might cause problems later when
        // decoded on different system.
        String username = userAttributes.getFirst(UserModel.USERNAME);
        String userId = Base64Url.encode(username.getBytes(StandardCharsets.UTF_8));
        Challenge challenge = new DefaultChallenge();
        String challengeValue = Base64Url.encode(challenge.getValue());
        context.getAuthenticationSession().setAuthNote(WebAuthnConstants.AUTH_CHALLENGE_NOTE, challengeValue);

        // construct parameters for calling WebAuthn API navigator.credential.create()

        // mandatory
        WebAuthnPolicy policy = getWebAuthnPolicy(context);
        List<String> signatureAlgorithmsList = policy.getSignatureAlgorithm();
        // Convert human-readable algorithms to their COSE identifier form
        List<Long> signatureAlgorithms = convertSignatureAlgorithms(signatureAlgorithmsList);
        String rpEntityName = policy.getRpEntityName();

        // optional
        String rpId = policy.getRpId();
        if (rpId == null || rpId.isEmpty())
            rpId = context.getUriInfo().getBaseUri().getHost();
        String attestationConveyancePreference = policy.getAttestationConveyancePreference();
        String authenticatorAttachment = policy.getAuthenticatorAttachment();
        String requireResidentKey = policy.getRequireResidentKey();
        String userVerificationRequirement = policy.getUserVerificationRequirement();
        long createTimeout = policy.getCreateTimeout();

        String excludeCredentialIds = "";

        String isSetRetry = null;

        if (isFormDataRequest(context.getHttpRequest())) {
            isSetRetry = context.getHttpRequest().getDecodedFormParameters()
                    .getFirst(WebAuthnConstants.IS_SET_RETRY);
        }

        Response form = context.form()
                .setAttribute(WebAuthnConstants.CHALLENGE, challengeValue)
                .setAttribute(WebAuthnConstants.USER_ID, userId)
                .setAttribute(WebAuthnConstants.USER_NAME, username)
                .setAttribute(WebAuthnConstants.RP_ENTITY_NAME, rpEntityName)
                .setAttribute(WebAuthnConstants.SIGNATURE_ALGORITHMS, signatureAlgorithms)
                .setAttribute(WebAuthnConstants.RP_ID, rpId)
                .setAttribute(WebAuthnConstants.ATTESTATION_CONVEYANCE_PREFERENCE, attestationConveyancePreference)
                .setAttribute(WebAuthnConstants.AUTHENTICATOR_ATTACHMENT, authenticatorAttachment)
                .setAttribute(WebAuthnConstants.REQUIRE_RESIDENT_KEY, requireResidentKey)
                .setAttribute(WebAuthnConstants.USER_VERIFICATION_REQUIREMENT, userVerificationRequirement)
                .setAttribute(WebAuthnConstants.CREATE_TIMEOUT, createTimeout)
                .setAttribute(WebAuthnConstants.EXCLUDE_CREDENTIAL_IDS, excludeCredentialIds)
                .setAttribute(WebAuthnConstants.IS_SET_RETRY, isSetRetry)
                .createForm(TPL_CODE);
        context.challenge(form);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();

        // The setup type (whether the user wants to set up a passkey or a password) is
        // passed via form parameter
        String setupType = params.getFirst(SETUP_TYPE);
        System.out.println(params);

        if (setupType.equals(SETUP_PASSKEY)) {
            Utils.createUserFromAuthSessionNotes(context);
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

    /**
     * Converts a list of human-readable webauthn signature methods (ES256, RS256,
     * etc) into
     * their <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">
     * COSE identifier</a> form.
     *
     * Returns the list of converted algorithm identifiers.
     **/
    private List<Long> convertSignatureAlgorithms(List<String> signatureAlgorithmsList) {
        List<Long> algs = new ArrayList();
        if (signatureAlgorithmsList == null || signatureAlgorithmsList.isEmpty())
            return algs;

        for (String s : signatureAlgorithmsList) {
            switch (s) {
                case Algorithm.ES256:
                    algs.add(COSEAlgorithmIdentifier.ES256.getValue());
                    break;
                case Algorithm.RS256:
                    algs.add(COSEAlgorithmIdentifier.RS256.getValue());
                    break;
                case Algorithm.ES384:
                    algs.add(COSEAlgorithmIdentifier.ES384.getValue());
                    break;
                case Algorithm.RS384:
                    algs.add(COSEAlgorithmIdentifier.RS384.getValue());
                    break;
                case Algorithm.ES512:
                    algs.add(COSEAlgorithmIdentifier.ES512.getValue());
                    break;
                case Algorithm.RS512:
                    algs.add(COSEAlgorithmIdentifier.RS512.getValue());
                    break;
                case Algorithm.Ed25519:
                    algs.add(COSEAlgorithmIdentifier.EdDSA.getValue());
                    break;
                case "RS1":
                    algs.add(COSEAlgorithmIdentifier.RS1.getValue());
                    break;
                default:
                    // NOP
            }
        }

        return algs;
    }

    protected WebAuthnPolicy getWebAuthnPolicy(AuthenticationFlowContext context) {
        return context.getRealm().getWebAuthnPolicy();
    }

    private boolean isFormDataRequest(HttpRequest request) {
        MediaType mediaType = request.getHttpHeaders().getMediaType();
        return mediaType != null && mediaType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }
}
