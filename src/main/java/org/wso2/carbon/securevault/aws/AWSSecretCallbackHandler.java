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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.secret.AbstractSecretCallbackHandler;
import org.wso2.securevault.secret.SingleSecretCallback;
import static org.wso2.carbon.securevault.aws.AWSVaultConstants.CONFIG_FILE_PATH;
import static org.wso2.carbon.securevault.aws.AWSVaultConstants.IDENTITY_KEY_PASSWORD_ALIAS;
import static org.wso2.carbon.securevault.aws.AWSVaultConstants.IDENTITY_STORE_PASSWORD_ALIAS;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;


/**
 * Secret Callback handler class if keystore and primary key passwords are stored in the
 * AWS Vault.
 */
public class AWSSecretCallbackHandler extends AbstractSecretCallbackHandler {
    private static final Log log = LogFactory.getLog(AWSSecretCallbackHandler.class);
    private static String keyStorePassword;
    private static String privateKeyPassword;

    /**
     * Handles single secret callback.
     *
     * @param singleSecretCallback a single secret callback
     */
    @Override
    protected void handleSingleSecretCallback(SingleSecretCallback singleSecretCallback) {
        if (keyStorePassword == null && privateKeyPassword == null) {
            boolean sameKeyAndKeyStorePass = true;
            String keyPassword = System.getProperty("key.password");
            if (keyPassword != null && keyPassword.trim().equals("true")) {
                sameKeyAndKeyStorePass = false;
            }
            readPassword(sameKeyAndKeyStorePass);
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
     * @param sameKeyAndKeyStorePass flag to indicate whether the keystore and primary key passwords are the same
     */
    private void readPassword(boolean sameKeyAndKeyStorePass) {
        if (log.isDebugEnabled()) {
            log.debug("Reading configuration properties from file.");
        }
        InputStream inputStream = null;
        Properties properties = new Properties();
        try {
            inputStream = new FileInputStream(CONFIG_FILE_PATH);
            properties.load(inputStream);
        } catch (Exception e) {
            throw new SecureVaultException("Error while loading configurations from " + CONFIG_FILE_PATH, e);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                log.warn("Error closing input stream of configuration file");
            }
        }

        AWSSecretRepository awsSecretRepository = new AWSSecretRepository();
        String keyStoreAlias = properties.getProperty(IDENTITY_STORE_PASSWORD_ALIAS);
        String privateKeyAlias = properties.getProperty(IDENTITY_KEY_PASSWORD_ALIAS);
        keyStorePassword = awsSecretRepository.getSecret(keyStoreAlias);
        if (sameKeyAndKeyStorePass) {
            privateKeyPassword = keyStorePassword;
        } else {
            privateKeyPassword = awsSecretRepository.getSecret(privateKeyAlias);
        }
    }


}
