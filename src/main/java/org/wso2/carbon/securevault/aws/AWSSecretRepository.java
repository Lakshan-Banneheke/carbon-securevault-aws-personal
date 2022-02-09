package org.wso2.carbon.securevault.aws;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

import java.util.Properties;

public class AWSSecretRepository implements SecretRepository {

    private static final Log LOG = LogFactory.getLog(AWSSecretRepository.class);

    private IdentityKeyStoreWrapper identityKeyStoreWrapper;
    private TrustKeyStoreWrapper trustKeyStoreWrapper;

    private SecretRepository parentRepository;

    private SecretsManagerClient secretsClient;

    public AWSSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                                     TrustKeyStoreWrapper trustKeyStoreWrapper) {

        this.identityKeyStoreWrapper = identityKeyStoreWrapper;
        this.trustKeyStoreWrapper = trustKeyStoreWrapper;
    }

    @Override
    public void init(Properties properties, String id) {
        LOG.info("Initializing AWS Secure Vault");
        secretsClient = SecretsManagerClient.builder()
                .build();
        LOG.info("AWS Secrets Client built");
    }

    public String getSecret(String alias) {
        String secret = null;
        try {
//            GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
//                    .secretId(alias)
//                    .build();
//
//            GetSecretValueResponse valueResponse = secretsClient.getSecretValue(valueRequest);
//            secret = valueResponse.secretString();
//            LOG.info("Secret retrieved");
//            LOG.info("SECRET IS " + secret);

        } catch (SecretsManagerException e) {
//            LOG.error(e.awsErrorDetails().errorMessage());
//            System.exit(1);
        }
        return secret;
    }


    public String getEncryptedData(String s) {
        throw new UnsupportedOperationException();
    }

    public void setParent(SecretRepository parent) {
        this.parentRepository = parent;
    }

    public SecretRepository getParent() {
        return this.parentRepository;
    }
}


