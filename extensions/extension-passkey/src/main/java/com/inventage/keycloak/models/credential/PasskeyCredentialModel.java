package com.inventage.keycloak.models.credential;

/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import java.io.IOException;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.credential.dto.WebAuthnCredentialData;
import org.keycloak.models.credential.dto.WebAuthnSecretData;
import org.keycloak.util.JsonSerialization;

import java.util.Collections;
import java.util.Set;

/**
 * @author <a href="mailto:dev@pcad.it">Pier Carlo Cadoppi</a>
 */
public class PasskeyCredentialModel extends CredentialModel {

    // Credential type used for Passkey credentials
    public static final String TYPE = "passkey";

    // Either
    private final WebAuthnCredentialData credentialData;
    private final WebAuthnSecretData secretData;

    private PasskeyCredentialModel(String credentialType, WebAuthnCredentialData credentialData,
            WebAuthnSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
        setType(credentialType);
    }

    public static PasskeyCredentialModel create(String credentialType, String userLabel, String aaguid,
            String credentialId,
            String attestationStatement, String credentialPublicKey, long counter, String attestationStatementFormat) {
        return create(credentialType, userLabel, aaguid, credentialId, attestationStatement, credentialPublicKey,
                counter, attestationStatementFormat, Collections.emptySet());
    }

    public static PasskeyCredentialModel create(String credentialType, String userLabel, String aaguid,
            String credentialId,
            String attestationStatement, String credentialPublicKey, long counter, String attestationStatementFormat,
            Set<String> transports) {
        WebAuthnCredentialData credentialData = new WebAuthnCredentialData(aaguid, credentialId, counter,
                attestationStatement, credentialPublicKey, attestationStatementFormat, transports);
        WebAuthnSecretData secretData = new WebAuthnSecretData();

        PasskeyCredentialModel credentialModel = new PasskeyCredentialModel(credentialType, credentialData,
                secretData);
        credentialModel.fillCredentialModelFields();
        credentialModel.setUserLabel(userLabel);
        return credentialModel;
    }

    public static PasskeyCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
            WebAuthnCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(),
                    WebAuthnCredentialData.class);
            WebAuthnSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(),
                    WebAuthnSecretData.class);

            PasskeyCredentialModel passkeyCredentialModel = new PasskeyCredentialModel(credentialModel.getType(),
                    credentialData, secretData);
            passkeyCredentialModel.setUserLabel(credentialModel.getUserLabel());
            passkeyCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
            passkeyCredentialModel.setType(credentialModel.getType());
            passkeyCredentialModel.setId(credentialModel.getId());
            passkeyCredentialModel.setSecretData(credentialModel.getSecretData());
            passkeyCredentialModel.setCredentialData(credentialModel.getCredentialData());
            return passkeyCredentialModel;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void updateCounter(long counter) {
        credentialData.setCounter(counter);
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public WebAuthnCredentialData getWebAuthnCredentialData() {
        return credentialData;
    }

    public WebAuthnSecretData getWebAuthnSecretData() {
        return secretData;
    }

    private void fillCredentialModelFields() {
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            setSecretData(JsonSerialization.writeValueAsString(secretData));
            setCreatedDate(Time.currentTimeMillis());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return "PasskeyCredentialModel { " +
                getType() +
                ", " + credentialData +
                ", " + secretData +
                " }";
    }
}
