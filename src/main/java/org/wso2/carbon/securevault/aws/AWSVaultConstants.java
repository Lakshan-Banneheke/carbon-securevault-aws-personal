package org.wso2.carbon.securevault.aws;

import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;

public class AWSVaultConstants {

    public static final String AWS_REGION_PARAMETER = "secretRepositories.vault.properties.awsregion";
    public static final String CONFIG_FILE_PATH = CarbonUtils.getCarbonConfigDirPath() + File.separator +
            "security" + File.separator + "secret-conf.properties";
    public static final String IDENTITY_STORE_PASSWORD_ALIAS = "keystore.identity.store.alias";
    public static final String IDENTITY_KEY_PASSWORD_ALIAS = "keystore.identity.key.alias";
    public static final String CREDENTIAL_PROVIDERS = "secretRepositories.vault.properties.credentialProviders";

}
