package com.inventage.keycloak.credential;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProvider;

import com.google.auto.service.AutoService;

import com.webauthn4j.converter.util.ObjectConverter;
import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

@AutoService(CredentialProviderFactory.class)
public class PasskeyRegistrationCredentialProviderFactory implements
        CredentialProviderFactory<PasskeyRegistrationCredentialProvider>, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "keycloak-passkey-credential-provider";

    private ObjectConverter converter;

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new PasskeyRegistrationCredentialProvider(session, createOrGetObjectConverter());
    }

    private ObjectConverter createOrGetObjectConverter() {
        if (converter == null) {
            synchronized (this) {
                if (converter == null) {
                    converter = new ObjectConverter();
                }
            }
        }
        return converter;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.WEB_AUTHN);
    }

}
