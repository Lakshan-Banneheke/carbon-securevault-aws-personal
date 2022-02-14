package org.wso2.carbon.securevault.aws;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
     * @param sameKeyAndKeyStorePass flag to indicate whether the keystore and primary key passwords are the same
     */
    private void readPassword(boolean sameKeyAndKeyStorePass) throws AWSVaultException {
        if (log.isDebugEnabled()) {
            log.debug("Reading configuration properties from file.");
        }
        InputStream inputStream = null;
        Properties properties = new Properties();
        try {
            inputStream = new FileInputStream(CONFIG_FILE_PATH);
            properties.load(inputStream);
        } catch (Exception e) {
            throw new AWSVaultException("Error while loading configurations from " + CONFIG_FILE_PATH);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                log.warn("Error closing input stream of configuration file");
            }
        }

        String keyStoreAlias = properties.getProperty(IDENTITY_STORE_PASSWORD_ALIAS);
        String privateKeyAlias = properties.getProperty(IDENTITY_KEY_PASSWORD_ALIAS);

        if (StringUtils.isEmpty(keyStoreAlias)){
            throw new AWSVaultException("keystore.identity.store.alias property has not been set. Unable to retrieve root keystore password from AWS Secrets Manager.");
        } else if (StringUtils.isEmpty(privateKeyAlias) && !sameKeyAndKeyStorePass ) {
            throw new AWSVaultException("keystore.identity.key.alias property has not been set. Unable to retrieve root private key from AWS Secrets Manager.");
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
