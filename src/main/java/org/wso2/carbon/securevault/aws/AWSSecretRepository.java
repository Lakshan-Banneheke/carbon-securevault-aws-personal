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
import org.wso2.securevault.secret.SecretRepository;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

import java.util.Properties;

/**
 * AWS Secret Repository.
 */
public class AWSSecretRepository implements SecretRepository {

    private static final Log log = LogFactory.getLog(AWSSecretRepository.class);

    private SecretRepository parentRepository;
    // Secret Client used to retrieve secrets from AWS Secrets Manager Vault
    private SecretsManagerClient secretsClient;

    /**
     * Initializes the AWS Secret repository based on provided properties.
     *
     * @param properties Configuration properties
     * @param id         Identifier to identify properties related to the corresponding repository
     */
    @Override
    public void init(Properties properties, String id) {
        log.info("Initializing AWS Secure Vault");
        secretsClient = AWSSecretManagerClient.getInstance(properties);
    }

    /**
     * Get Secret from AWS Secrets Manager.
     *
     * @param alias Name and version of the secret being retrieved separated by a "#". The version is optional.
     * @return Secret retrieved from the AWS Secrets Manager if there is any, otherwise, alias itself.
     * @see SecretRepository
     */
    @Override
    public String getSecret(String alias) {

        if (StringUtils.isEmpty(alias)) {
            return alias;
        }

        String secret = alias;

        try {
            String[] versionDetails = getSecretVersion(alias);
            String secretName = versionDetails[0];
            String secretVersion = versionDetails[1];

            GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
                    .secretId(secretName)
                    .versionId(secretVersion)
                    .build();

            GetSecretValueResponse valueResponse = secretsClient.getSecretValue(valueRequest);
            secret = valueResponse.secretString();

            if (log.isDebugEnabled()) {
                log.debug("Secret " + secretName + " is retrieved");
            }

        } catch (SecretsManagerException e) {
            log.error("Error retrieving secret with alias " + alias + " from AWS Secrets Manager Vault.");
            log.error(e.awsErrorDetails().errorMessage());
        } catch (SdkClientException e) {
            log.error("Error establishing connection to AWS");
            log.error(e.getMessage());
        }
        return secret;
    }

    /**
     * Get Encrypted data. This is not supported in this extension.
     *
     * @param alias Alias of the secret
     */
    @Override
    public String getEncryptedData(String alias) {

        throw new UnsupportedOperationException();
    }

    /**
     * Get parent repository.
     *
     * @return Parent repository
     */
    @Override
    public SecretRepository getParent() {

        return this.parentRepository;
    }

    /**
     * Set parent repository.
     *
     * @param parent Parent secret repository
     */
    @Override
    public void setParent(SecretRepository parent) {

        this.parentRepository = parent;
    }

    /**
     * Util method to get the secret name and version.
     * If no secret version is set, it will return null for versionID,
     * which will return the latest version of the secret from the AWS Secrets Manager.
     *
     * @param alias The alias of the secret.
     * @return An array with the secret name and the secret version
     */
    private String[] getSecretVersion(String alias) {

        String secretName = alias;
        String secretVersion = null;

        if (alias.contains("#")) {
            int underscoreIndex = alias.indexOf("#");
            secretName = alias.substring(0, underscoreIndex);
            secretVersion = alias.substring(underscoreIndex + 1);
            if (log.isDebugEnabled()) {
                log.debug("Secret version found for " + secretName + ". Retrieving the specified version of secret.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Secret version not found for " + secretName + ". Retrieving latest version of secret.");
            }
        }
        return new String[]{secretName, secretVersion};
    }
}


