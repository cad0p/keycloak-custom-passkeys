package com.inventage.keycloak.registration;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.requiredactions.WebAuthnRegister;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.CollectionUtil;
import org.keycloak.common.util.UriUtils;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.crypto.Algorithm;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

import com.inventage.keycloak.credential.PasskeyRegistrationCredentialProviderFactory;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;

import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.validator.attestation.statement.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.TPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;

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
public class PasskeyRegistrationAuthenticator implements Authenticator, CredentialRegistrator {

    private static final String WEB_AUTHN_TITLE_ATTR = "webAuthnTitle";
    private static final Logger logger = Logger.getLogger(WebAuthnRegister.class);

    private KeycloakSession session;
    private CertPathTrustworthinessValidator certPathtrustValidator;

    public PasskeyRegistrationAuthenticator(
            KeycloakSession session,
            CertPathTrustworthinessValidator certPathtrustValidator) {
        this.session = session;
        this.certPathtrustValidator = certPathtrustValidator;
    }

    public static final String SETUP_TYPE = "setupType";
    public static final String SETUP_PASSKEY = "passkey";
    private static final String TPL_CODE = "passkey-registration.ftl";

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        // Create a minimal user to get the user id
        UserModel user = Utils.createMinimalUser(context);
        MultivaluedMap<String, String> userAttributes = Utils.getUserDataFromAuthSessionNotes(context);
        // Use standard UTF-8 charset to get bytes from string.
        // Otherwise the platform's default charset is used and it might cause problems later when
        // decoded on different system.
        String username = userAttributes.getFirst(UserModel.USERNAME);
        String userId = Base64Url.encode(user.getId().getBytes(StandardCharsets.UTF_8));
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

        String isSetRetry = params.getFirst(WebAuthnConstants.IS_SET_RETRY);
        if (isSetRetry != null && !isSetRetry.isEmpty()) {
            authenticate(context);
            return;
        }

        String userId = params.getFirst(WebAuthnConstants.USER_ID);

        final EventType eventType = EventType.UPDATE_CREDENTIAL;
        context.getEvent()
                .event(EventType.UPDATE_CREDENTIAL)
                .detail(Details.CREDENTIAL_TYPE, getCredentialType());

        // receive error from navigator.credentials.create()
        String errorMsgFromWebAuthnApi = params.getFirst(WebAuthnConstants.ERROR);
        if (errorMsgFromWebAuthnApi != null && !errorMsgFromWebAuthnApi.isEmpty()) {
            setErrorResponse(context, Messages.WEBAUTHN_ERROR_REGISTER_VERIFICATION, errorMsgFromWebAuthnApi,
                    eventType);
            return;
        }

        WebAuthnPolicy policy = getWebAuthnPolicy(context);
        String rpId = policy.getRpId();
        if (rpId == null || rpId.isEmpty())
            rpId = context.getUriInfo().getBaseUri().getHost();
        String label = params.getFirst(WebAuthnConstants.AUTHENTICATOR_LABEL);
        byte[] clientDataJSON = Base64.getUrlDecoder().decode(params.getFirst(WebAuthnConstants.CLIENT_DATA_JSON));
        byte[] attestationObject = Base64.getUrlDecoder().decode(params.getFirst(WebAuthnConstants.ATTESTATION_OBJECT));

        String publicKeyCredentialId = params.getFirst(WebAuthnConstants.PUBLIC_KEY_CREDENTIAL_ID);

        Origin origin = new Origin(UriUtils.getOrigin(context.getUriInfo().getBaseUri()));
        Challenge challenge = new DefaultChallenge(
                context.getAuthenticationSession().getAuthNote(WebAuthnConstants.AUTH_CHALLENGE_NOTE));
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        // check User Verification by considering a malicious user might modify the result of calling WebAuthn API
        boolean isUserVerificationRequired = policy.getUserVerificationRequirement()
                .equals(WebAuthnConstants.OPTION_REQUIRED);

        final String transportsParam = params.getFirst(WebAuthnConstants.TRANSPORTS);

        RegistrationRequest registrationRequest;

        if (StringUtil.isNotBlank(transportsParam)) {
            final Set<String> transports = new HashSet<>(Arrays.asList(transportsParam.split(",")));
            registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON, transports);
        } else {
            registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON);
        }

        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty,
                isUserVerificationRequired);

        WebAuthnRegistrationManager webAuthnRegistrationManager = createWebAuthnRegistrationManager();
        try {
            // parse
            RegistrationData registrationData = webAuthnRegistrationManager.parse(registrationRequest);
            // validate
            webAuthnRegistrationManager.validate(registrationData, registrationParameters);

            showInfoAfterWebAuthnApiCreate(registrationData);

            checkAcceptedAuthenticator(registrationData, policy);

            WebAuthnCredentialModelInput credential = new WebAuthnCredentialModelInput(getCredentialType());

            credential.setAttestedCredentialData(
                    registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData());
            credential.setCount(registrationData.getAttestationObject().getAuthenticatorData().getSignCount());
            credential.setAttestationStatementFormat(registrationData.getAttestationObject().getFormat());
            credential.setTransports(registrationData.getTransports());

            // Save new webAuthn credential
            WebAuthnCredentialProvider webAuthnCredProvider = (WebAuthnCredentialProvider) this.session
                    .getProvider(CredentialProvider.class, getCredentialProviderId());
            WebAuthnCredentialModel newCredentialModel = webAuthnCredProvider
                    .getCredentialModelFromCredentialInput(credential, label);

            Utils.createOrUpdateUserFromAuthSessionNotes(context);
            webAuthnCredProvider.createCredential(context.getRealm(), context.getUser(), newCredentialModel);

            String aaguid = newCredentialModel.getWebAuthnCredentialData().getAaguid();
            logger.debugv(
                    "WebAuthn credential registration success for user {0}. credentialType = {1}, publicKeyCredentialId = {2}, publicKeyCredentialLabel = {3}, publicKeyCredentialAAGUID = {4}",
                    context.getUser().getUsername(), getCredentialType(), publicKeyCredentialId, label, aaguid);
            webAuthnCredProvider.dumpCredentialModel(newCredentialModel, credential);

            context.getEvent()
                    .detail(WebAuthnConstants.PUBKEY_CRED_ID_ATTR, publicKeyCredentialId)
                    .detail(WebAuthnConstants.PUBKEY_CRED_LABEL_ATTR, label)
                    .detail(WebAuthnConstants.PUBKEY_CRED_AAGUID_ATTR, aaguid);
            context.getEvent().clone().event(eventType).success();
            context.success();
        } catch (WebAuthnException wae) {
            context.attempted();
            if (logger.isDebugEnabled())
                logger.debug(wae.getMessage(), wae);
            setErrorResponse(context, Messages.WEBAUTHN_ERROR_REGISTRATION, wae.getMessage(), eventType);
            return;
        } catch (Exception e) {
            context.attempted();
            if (logger.isDebugEnabled())
                logger.debug(e.getMessage(), e);
            setErrorResponse(context, Messages.WEBAUTHN_ERROR_REGISTRATION, e.getMessage(), eventType);
            return;
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

    @Override
    public String getCredentialType(KeycloakSession session, AuthenticationSessionModel authenticationSession) {
        return getCredentialType();
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

    private String getCredentialType() {
        return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    }

    private void setErrorResponse(AuthenticationFlowContext context, final String errorCase, final String errorMessage,
            @Deprecated final EventType originalEventType) {
        Response errorResponse = null;
        switch (errorCase) {
            case Messages.WEBAUTHN_ERROR_REGISTER_VERIFICATION:
                logger.warnv("WebAuthn API .create() response validation failure. {0}", errorMessage);
                EventBuilder registerVerificationEvent = context.getEvent()
                        .detail(WebAuthnConstants.REG_ERR_LABEL, errorCase)
                        .detail(WebAuthnConstants.REG_ERR_DETAIL_LABEL, errorMessage);
                EventBuilder deprecatedRegisterVerificationEvent = registerVerificationEvent.clone()
                        .event(originalEventType);
                registerVerificationEvent.error(Errors.INVALID_USER_CREDENTIALS);
                deprecatedRegisterVerificationEvent.error(Errors.INVALID_USER_CREDENTIALS);
                errorResponse = context.form()
                        .setError(errorCase, errorMessage)
                        .setAttribute(WEB_AUTHN_TITLE_ATTR, Messages.WEBAUTHN_REGISTER_TITLE)
                        .createWebAuthnErrorPage();
                context.challenge(errorResponse);
                break;
            case Messages.WEBAUTHN_ERROR_REGISTRATION:
                logger.warn(errorCase);
                EventBuilder registrationEvent = context.getEvent()
                        .detail(WebAuthnConstants.REG_ERR_LABEL, errorCase)
                        .detail(WebAuthnConstants.REG_ERR_DETAIL_LABEL, errorMessage);
                EventBuilder deprecatedRegistrationEvent = registrationEvent.clone().event(originalEventType);
                deprecatedRegistrationEvent.error(Errors.INVALID_REGISTRATION);
                registrationEvent.error(Errors.INVALID_REGISTRATION);
                errorResponse = context.form()
                        .setError(errorCase, errorMessage)
                        .setAttribute(WEB_AUTHN_TITLE_ATTR, Messages.WEBAUTHN_REGISTER_TITLE)
                        .createWebAuthnErrorPage();
                throw new WebAuthnException(errorCase + ": " + errorMessage);
            // context.challenge(errorResponse);
            // break;
            default:
                // NOP
        }
    }

    /**
     * Create WebAuthnRegistrationManager instance
     * Can be overridden in subclasses to customize the used attestation validators
     *
     * @return webauthn4j WebAuthnRegistrationManager instance
     */
    protected WebAuthnRegistrationManager createWebAuthnRegistrationManager() {
        return new WebAuthnRegistrationManager(
                Arrays.asList(
                        new NoneAttestationStatementValidator(),
                        new PackedAttestationStatementValidator(),
                        new TPMAttestationStatementValidator(),
                        new AndroidKeyAttestationStatementValidator(),
                        new AndroidSafetyNetAttestationStatementValidator(),
                        new FIDOU2FAttestationStatementValidator()),
                this.certPathtrustValidator,
                new DefaultSelfAttestationTrustworthinessValidator(),
                Collections.emptyList(), // Custom Registration Validator is not supported
                new ObjectConverter());
    }

    private void showInfoAfterWebAuthnApiCreate(RegistrationData response) {
        AttestedCredentialData attestedCredentialData = response.getAttestationObject().getAuthenticatorData()
                .getAttestedCredentialData();
        AttestationStatement attestationStatement = response.getAttestationObject().getAttestationStatement();
        Set<AuthenticatorTransport> transports = response.getTransports();

        logger.debugv("createad key's algorithm = {0}",
                String.valueOf(attestedCredentialData.getCOSEKey().getAlgorithm().getValue()));
        logger.debugv("aaguid = {0}", attestedCredentialData.getAaguid().toString());
        logger.debugv("attestation format = {0}", attestationStatement.getFormat());

        if (CollectionUtil.isNotEmpty(transports)) {
            logger.debugv("transports = [{0}]", transports.stream()
                    .map(AuthenticatorTransport::getValue)
                    .collect(Collectors.joining(",")));
        }
    }

    private void checkAcceptedAuthenticator(RegistrationData response, WebAuthnPolicy policy) throws Exception {
        String aaguid = response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid()
                .toString();
        List<String> acceptableAaguids = policy.getAcceptableAaguids();
        boolean isAcceptedAuthenticator = false;
        if (acceptableAaguids != null && !acceptableAaguids.isEmpty()) {
            for (String acceptableAaguid : acceptableAaguids) {
                if (aaguid.equals(acceptableAaguid)) {
                    isAcceptedAuthenticator = true;
                    break;
                }
            }
        } else {
            // no accepted authenticators means accepting any kind of authenticator
            isAcceptedAuthenticator = true;
        }
        if (!isAcceptedAuthenticator) {
            throw new WebAuthnException("not acceptable aaguid = " + aaguid);
        }
    }

    protected String getCredentialProviderId() {
        return PasskeyRegistrationCredentialProviderFactory.PROVIDER_ID;
    }

}
