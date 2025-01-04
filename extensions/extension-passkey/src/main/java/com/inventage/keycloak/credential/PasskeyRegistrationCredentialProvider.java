package com.inventage.keycloak.credential;

import com.inventage.keycloak.registration.PasskeyRegistrationAuthenticatorFactory;
import com.webauthn4j.converter.util.ObjectConverter;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;

/**
 * Credential provider for WebAuthn passwordless credential of the user
 *
 * @author <a href="mailto:dev@pcad.it">Pier Carlo Cadoppi</a>
 */
public class PasskeyRegistrationCredentialProvider extends WebAuthnCredentialProvider {

    public PasskeyRegistrationCredentialProvider(KeycloakSession session, ObjectConverter objectConverter) {
        super(session, objectConverter);
    }

    @Override
    public String getType() {
        return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
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
                .build(getKeycloakSession());
    }

    @Override
    protected WebAuthnPolicy getWebAuthnPolicy() {
        return getKeycloakSession().getContext().getRealm().getWebAuthnPolicyPasswordless();
    }
}
