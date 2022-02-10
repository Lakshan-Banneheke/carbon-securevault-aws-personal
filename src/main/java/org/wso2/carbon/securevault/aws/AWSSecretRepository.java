package org.wso2.carbon.securevault.aws;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import software.amazon.awssdk.regions.Region;
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

    private IdentityKeyStoreWrapper identityKeyStoreWrapper;
    private TrustKeyStoreWrapper trustKeyStoreWrapper;
    private SecretRepository parentRepository;
    private SecretsManagerClient secretsClient;


    public AWSSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                                     TrustKeyStoreWrapper trustKeyStoreWrapper) {

        this.identityKeyStoreWrapper = identityKeyStoreWrapper;
        this.trustKeyStoreWrapper = trustKeyStoreWrapper;
    }

    /**
     * Initializes the AWS Secret repository based on provided properties.
     *
     * @param properties Configuration properties
     * @param id         Identifier to identify properties related to the corresponding repository
     */
    @Override
    public void init(Properties properties, String id) {
        log.info("Initializing AWS Secure Vault");

        try {
            Region region = AWSVaultUtils.getAWSRegion(properties);
            secretsClient = SecretsManagerClient.builder()
                    .region(region)
                    .build();

        } catch (AWSVaultException e) {
            log.error(e.getMessage(), e);
        }
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
            GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
                    .secretId(alias)
                    .build();

            GetSecretValueResponse valueResponse = secretsClient.getSecretValue(valueRequest);
            secret = valueResponse.secretString();
            if (log.isDebugEnabled()) {
                log.debug("Secret " + alias + " is retrieved");
            }

            //TODO remove these logs
            log.info("Secret retrieved");
            log.info("SECRET IS " + secret);

        } catch (SecretsManagerException e) {
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
}


