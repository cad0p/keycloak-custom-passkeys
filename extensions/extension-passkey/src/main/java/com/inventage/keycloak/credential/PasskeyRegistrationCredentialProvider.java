package com.inventage.keycloak.credential;

import com.inventage.keycloak.models.credential.PasskeyCredentialModel;
import com.inventage.keycloak.registration.PasskeyRegistrationAuthenticatorFactory;
import com.webauthn4j.WebAuthnAuthenticationManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.validator.OriginValidatorImpl;
import com.webauthn4j.validator.exception.BadOriginException;

import jakarta.annotation.Nonnull;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.Time;
import org.keycloak.credential.AttestationStatementConverter;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialPublicKeyConverter;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.models.credential.dto.WebAuthnCredentialData;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Credential provider for WebAuthn passwordless credential of the user
 *
 * @author <a href="mailto:dev@pcad.it">Pier Carlo Cadoppi</a>
 */
public class PasskeyRegistrationCredentialProvider
        implements CredentialProvider<PasskeyCredentialModel>, CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(PasskeyRegistrationCredentialProvider.class);

    private KeycloakSession session;

    private CredentialPublicKeyConverter credentialPublicKeyConverter;
    private AttestationStatementConverter attestationStatementConverter;

    public PasskeyRegistrationCredentialProvider(KeycloakSession session, ObjectConverter objectConverter) {
        this.session = session;
        if (credentialPublicKeyConverter == null)
            credentialPublicKeyConverter = new CredentialPublicKeyConverter(objectConverter);
        if (attestationStatementConverter == null)
            attestationStatementConverter = new AttestationStatementConverter(objectConverter);
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, PasskeyCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }

        return user.credentialManager().createStoredCredential(credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        logger.debugv("Delete WebAuthn credential. username = {0}, credentialId = {1}", user.getUsername(),
                credentialId);
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public PasskeyCredentialModel getCredentialFromModel(CredentialModel model) {
        return PasskeyCredentialModel.createFromCredentialModel(model);
    }

    /**
     * Convert Passkey credential input to the model, which can be saved in the
     * persistent storage (DB)
     *
     * @param input
     *            should be typically WebAuthnCredentialModelInput
     * @param userLabel
     *            label for the credential
     */
    public PasskeyCredentialModel getCredentialModelFromCredentialInput(CredentialInput input, String userLabel) {
        if (!supportsCredentialType(input.getType()))
            return null;

        WebAuthnCredentialModelInput passkeyModel = (WebAuthnCredentialModelInput) input;

        String aaguid = passkeyModel.getAttestedCredentialData().getAaguid().toString();
        String credentialId = Base64.encodeBytes(passkeyModel.getAttestedCredentialData().getCredentialId());
        String credentialPublicKey = credentialPublicKeyConverter
                .convertToDatabaseColumn(passkeyModel.getAttestedCredentialData().getCOSEKey());
        long counter = passkeyModel.getCount();
        String attestationStatementFormat = passkeyModel.getAttestationStatementFormat();

        final Set<String> transports = passkeyModel.getTransports()
                .stream()
                .map(AuthenticatorTransport::getValue)
                .collect(Collectors.toSet());

        PasskeyCredentialModel model = PasskeyCredentialModel.create(
                getType(),
                userLabel,
                aaguid,
                credentialId,
                null,
                credentialPublicKey,
                counter,
                attestationStatementFormat,
                transports);

        model.setId(passkeyModel.getCredentialDBId());

        return model;
    }

    /**
     * Convert PasskeyCredentialModel, which was usually retrieved from DB, to the
     * CredentialInput, which contains data in the webauthn4j specific format
     */
    private WebAuthnCredentialModelInput getCredentialInputFromCredentialModel(CredentialModel credential) {
        PasskeyCredentialModel passkeyCredential = getCredentialFromModel(credential);

        WebAuthnCredentialData credData = passkeyCredential.getWebAuthnCredentialData();

        WebAuthnCredentialModelInput auth = new WebAuthnCredentialModelInput(getType());

        byte[] credentialId = null;
        try {
            credentialId = Base64.decode(credData.getCredentialId());
        } catch (IOException ioe) {
            // NOP
        }

        AAGUID aaguid = new AAGUID(credData.getAaguid());

        COSEKey pubKey = credentialPublicKeyConverter.convertToEntityAttribute(credData.getCredentialPublicKey());

        AttestedCredentialData attrCredData = new AttestedCredentialData(aaguid, credentialId, pubKey);

        auth.setAttestedCredentialData(attrCredData);

        long count = credData.getCounter();
        auth.setCount(count);

        auth.setCredentialDBId(credential.getId());

        auth.setAttestationStatementFormat(credData.getAttestationStatementFormat());

        return auth;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType))
            return false;
        return user.credentialManager().getStoredCredentialsByTypeStream(credentialType).count() > 0;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!WebAuthnCredentialModelInput.class.isInstance(input))
            return false;

        WebAuthnCredentialModelInput context = WebAuthnCredentialModelInput.class.cast(input);
        List<WebAuthnCredentialModelInput> auths = getWebAuthnCredentialModelList(realm, user);

        WebAuthnAuthenticationManager webAuthnAuthenticationManager = getWebAuthnAuthenticationManager();
        AuthenticationData authenticationData = null;

        try {
            for (WebAuthnCredentialModelInput auth : auths) {

                byte[] credentialId = auth.getAttestedCredentialData().getCredentialId();
                if (Arrays.equals(credentialId, context.getAuthenticationRequest().getCredentialId())) {
                    Authenticator authenticator = new AuthenticatorImpl(
                            auth.getAttestedCredentialData(),
                            auth.getAttestationStatement(),
                            auth.getCount());

                    // parse
                    authenticationData = webAuthnAuthenticationManager.parse(context.getAuthenticationRequest());
                    // validate
                    AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                            context.getAuthenticationParameters().getServerProperty(),
                            authenticator,
                            context.getAuthenticationParameters().isUserVerificationRequired());
                    webAuthnAuthenticationManager.validate(authenticationData, authenticationParameters);

                    logger.debugv("response.getAuthenticatorData().getFlags() = {0}",
                            authenticationData.getAuthenticatorData().getFlags());

                    CredentialModel credModel = user.credentialManager()
                            .getStoredCredentialById(auth.getCredentialDBId());
                    PasskeyCredentialModel passkeyCredModel = getCredentialFromModel(credModel);

                    // update authenticator counter
                    // counters are an optional feature of the spec - if an authenticator does not support them, it
                    // will always send zero. MacOS/iOS does this for keys stored in the secure enclave (TouchID/FaceID)
                    long count = auth.getCount();
                    if (count > 0) {
                        passkeyCredModel.updateCounter(count + 1);
                        user.credentialManager().updateStoredCredential(passkeyCredModel);
                    }

                    logger.debugf("Successfully validated WebAuthn credential for user %s", user.getUsername());
                    dumpCredentialModel(passkeyCredModel, auth);

                    return true;
                }
            }
        } catch (WebAuthnException wae) {
            wae.printStackTrace();
            throw (wae);
        }
        // no authenticator matched
        return false;
    }

    protected WebAuthnAuthenticationManager getWebAuthnAuthenticationManager() {
        WebAuthnPolicy policy = getWebAuthnPolicy();
        Set<Origin> origins = policy.getExtraOrigins().stream()
                .map(Origin::new)
                .collect(Collectors.toSet());
        WebAuthnAuthenticationManager webAuthnAuthenticationManager = new WebAuthnAuthenticationManager();
        webAuthnAuthenticationManager.getAuthenticationDataValidator().setOriginValidator(new OriginValidatorImpl() {
            @Override
            protected void validate(@Nonnull CollectedClientData collectedClientData,
                    @Nonnull ServerProperty serverProperty) {
                AssertUtil.notNull(collectedClientData, "collectedClientData must not be null");
                AssertUtil.notNull(serverProperty, "serverProperty must not be null");
                final Origin clientOrigin = collectedClientData.getOrigin();
                if (serverProperty.getOrigins().contains(clientOrigin))
                    return;
                // https://github.com/w3c/webauthn/issues/1297
                if (origins.contains(clientOrigin))
                    return;
                throw new BadOriginException("The collectedClientData '" + clientOrigin
                        + "' origin doesn't match any of the preconfigured origins.");
            }
        });
        return webAuthnAuthenticationManager;
    }

    protected WebAuthnPolicy getWebAuthnPolicy() {
        return session.getContext().getRealm().getWebAuthnPolicyPasswordless();
    }

    @Override
    public String getType() {
        return PasskeyCredentialModel.TYPE;
    }

    private List<WebAuthnCredentialModelInput> getWebAuthnCredentialModelList(RealmModel realm, UserModel user) {
        return user.credentialManager().getStoredCredentialsByTypeStream(getType())
                .map(this::getCredentialInputFromCredentialModel)
                .collect(Collectors.toList());
    }

    public void dumpCredentialModel(PasskeyCredentialModel credential, WebAuthnCredentialModelInput auth) {
        if (logger.isDebugEnabled()) {
            logger.debug("  Persisted Credential Info::");
            logger.debug(credential);
            logger.debug("  Context Credential Info::");
            logger.debug(auth);
        }
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.PASSWORDLESS)
                .displayName("webauthn-passwordless-display-name")
                .helpText("webauthn-passwordless-help-text")
                .iconCssClass("kcAuthenticatorWebAuthnPasswordlessClass")
                .createAction(PasskeyRegistrationAuthenticatorFactory.PROVIDER_ID)
                .removeable(true)
                .build(session);
    }

}
