package org.wso2.carbon.securevault.aws;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.secret.SecretRepository;
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
     * Get Secret from AWS Secrets Manager
     *
     * @param alias Alias name of the secret being retrieved
     * @return Secret if there is any, otherwise, alias itself
     * @see SecretRepository
     */
    public String getSecret(String alias) {
        if (StringUtils.isEmpty(alias)) {
            return alias;
        }

        String secret = alias;

        try {
            String[] versionDetails =  getSecretVersion(alias);
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
            log.error("Error retrieving secret with alias " + alias + " from AWS Secrets Manager Vault");
            log.error(e.awsErrorDetails().errorMessage());
        }
        return secret;
    }

    public String getEncryptedData(String alias) {
        throw new UnsupportedOperationException();
    }

    public void setParent(SecretRepository parent) {
        this.parentRepository = parent;
    }

    public SecretRepository getParent() {
        return this.parentRepository;
    }

    private String[] getSecretVersion(String alias){
        String secretName = alias;
        String secretVersion = null; //If no secret version is set, it will send the request with null set for versionID which will return the latest version from AWS Secrets Manager
        if (alias.contains("_")) {
            int underscoreIndex = alias.indexOf("_");
            secretName = alias.substring(0, underscoreIndex);
            secretVersion = alias.substring(underscoreIndex + 1);
            if (log.isDebugEnabled()) {
                log.debug("Secret version found for " + secretName  + ". Retrieving the specified version of secret.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Secret version not found for " + secretName  + ". Retrieving latest version of secret.");
            }
        }
        return new String[] {secretName, secretVersion};
    }
}


