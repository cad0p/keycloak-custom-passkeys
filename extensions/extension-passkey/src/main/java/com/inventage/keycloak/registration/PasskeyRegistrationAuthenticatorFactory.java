package com.inventage.keycloak.registration;

import com.google.auto.service.AutoService;
import com.webauthn4j.anchor.KeyStoreTrustAnchorsProvider;
import com.webauthn4j.anchor.TrustAnchorsResolverImpl;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.common.Profile;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.truststore.TruststoreProvider;

import java.util.List;

@AutoService(AuthenticatorFactory.class)
public class PasskeyRegistrationAuthenticatorFactory
        implements AuthenticatorFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "passkey-registration";
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public Authenticator create(KeycloakSession session) {
        PasskeyRegistrationAuthenticator webAuthnRegister = null;
        TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
        if (truststoreProvider == null || truststoreProvider.getTruststore() == null) {
            webAuthnRegister = createProvider(session, new NullCertPathTrustworthinessValidator());
        } else {
            KeyStoreTrustAnchorsProvider trustAnchorsProvider = new KeyStoreTrustAnchorsProvider();
            trustAnchorsProvider.setKeyStore(truststoreProvider.getTruststore());
            TrustAnchorsResolverImpl resolverImpl = new TrustAnchorsResolverImpl(trustAnchorsProvider);
            TrustAnchorCertPathTrustworthinessValidator trustValidator = new TrustAnchorCertPathTrustworthinessValidator(
                    resolverImpl);
            webAuthnRegister = createProvider(session, trustValidator);
        }
        return webAuthnRegister;
    }

    protected PasskeyRegistrationAuthenticator createProvider(KeycloakSession session,
            CertPathTrustworthinessValidator trustValidator) {
        return new PasskeyRegistrationAuthenticator(session, trustValidator);
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Register with Passkey (Recommended)";
    }

    @Override
    public String getReferenceCategory() {
        return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Register using your device's biometric sensor or security key (recommended)";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.WEB_AUTHN);
    }

}
