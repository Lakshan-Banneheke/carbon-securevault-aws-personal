package org.wso2.carbon.securevault.aws;

import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

public class AWSSecretRepositoryProvider implements SecretRepositoryProvider {
    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper, TrustKeyStoreWrapper trustKeyStoreWrapper) {
        return new AWSSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
    }
}
