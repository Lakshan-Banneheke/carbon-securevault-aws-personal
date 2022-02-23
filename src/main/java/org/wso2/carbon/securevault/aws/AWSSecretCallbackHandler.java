/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.securevault.aws;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.secret.AbstractSecretCallbackHandler;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.wso2.carbon.securevault.aws.AWSVaultConstants.CONFIG_FILE_PATH;
import static org.wso2.carbon.securevault.aws.AWSVaultConstants.IDENTITY_KEY_PASSWORD_ALIAS;
import static org.wso2.carbon.securevault.aws.AWSVaultConstants.IDENTITY_STORE_PASSWORD_ALIAS;

/**
 * Secret Callback handler class if keystore and primary key passwords are stored in the AWS Vault.
 */
public class AWSSecretCallbackHandler extends AbstractSecretCallbackHandler {

    private static final Log log = LogFactory.getLog(AWSSecretCallbackHandler.class);
    private static String keyStorePassword;
    private static String privateKeyPassword;

    /**
     * Handles single secret callback.
     *
     * @param singleSecretCallback A single secret callback.
     */
    @Override
    protected void handleSingleSecretCallback(SingleSecretCallback singleSecretCallback) {

        if (StringUtils.isEmpty(keyStorePassword) && StringUtils.isEmpty(privateKeyPassword)) {
            boolean sameKeyAndKeyStorePass = true;
            String keyPassword = System.getProperty("key.password");
            if (keyPassword != null && keyPassword.trim().equals("true")) {
                sameKeyAndKeyStorePass = false;
            }
            try {
                readPassword(sameKeyAndKeyStorePass);
            } catch (AWSVaultException e) {
                log.error(e.getMessage(), e);
            }
        }

        if (singleSecretCallback.getId().equals("identity.key.password")) {
            singleSecretCallback.setSecret(privateKeyPassword);
        } else {
            singleSecretCallback.setSecret(keyStorePassword);
        }

    }

    /**
     * Reads keystore and primary key passwords from AWS Vault.
     *
     * @param sameKeyAndKeyStorePass Flag to indicate whether the keystore and primary key passwords are the same.
     * @throws AWSVaultException If there are errors in loading configurations from the config file.
     */
    private void readPassword(boolean sameKeyAndKeyStorePass) throws AWSVaultException {

        if (log.isDebugEnabled()) {
            log.debug("Reading configuration properties from file.");
        }

        Properties properties = new Properties();

        try (InputStream inputStream = new FileInputStream(CONFIG_FILE_PATH)) {
            properties.load(inputStream);

        } catch (IOException e) {
            throw new AWSVaultException("Error while loading configurations from " + CONFIG_FILE_PATH);
        }

        String keyStoreAlias = properties.getProperty(IDENTITY_STORE_PASSWORD_ALIAS);
        String privateKeyAlias = properties.getProperty(IDENTITY_KEY_PASSWORD_ALIAS);

        if (StringUtils.isEmpty(keyStoreAlias)) {
            throw new AWSVaultException("keystore.identity.store.alias property has not been set. " +
                    "Unable to retrieve root keystore password from AWS Secrets Manager.");
        } else if (StringUtils.isEmpty(privateKeyAlias) && !sameKeyAndKeyStorePass) {
            throw new AWSVaultException("keystore.identity.key.alias property has not been set. " +
                    "Unable to retrieve root private key from AWS Secrets Manager.");
        }

        AWSSecretRepository awsSecretRepository = new AWSSecretRepository();
        awsSecretRepository.init(properties, "AWSSecretRepository");
        keyStorePassword = awsSecretRepository.getSecret(keyStoreAlias);
        if (sameKeyAndKeyStorePass) {
            privateKeyPassword = keyStorePassword;
        } else {
            privateKeyPassword = awsSecretRepository.getSecret(privateKeyAlias);
        }
    }
}
