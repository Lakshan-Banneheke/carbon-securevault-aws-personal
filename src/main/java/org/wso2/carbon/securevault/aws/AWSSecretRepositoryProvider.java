package org.wso2.carbon.securevault.aws;

import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

/**
 * AWS Secret Repository Provider.
 */
public class AWSSecretRepositoryProvider implements SecretRepositoryProvider {

    /**
     * Get Secret Repository.
     *
     * @param identityKeyStoreWrapper Identity KeyStore Wrapper
     * @param trustKeyStoreWrapper Trust KeyStore Wrapper
     * @return AWSSecretRepository
     */
    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper, TrustKeyStoreWrapper trustKeyStoreWrapper) {
        return new AWSSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
    }
}
