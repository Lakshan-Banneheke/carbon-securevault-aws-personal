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

import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;

/**
 * Constants used in the AWS Vault extension.
 */
public class AWSVaultConstants {

    private AWSVaultConstants(){}

    public static final String AWS_REGION_PARAMETER = "secretRepositories.vault.properties.awsregion";
    public static final String CONFIG_FILE_PATH = CarbonUtils.getCarbonConfigDirPath() + File.separator
            + "security" + File.separator + "secret-conf.properties";
    public static final String IDENTITY_STORE_PASSWORD_ALIAS = "keystore.identity.store.alias";
    public static final String IDENTITY_KEY_PASSWORD_ALIAS = "keystore.identity.key.alias";
    public static final String CREDENTIAL_PROVIDERS = "secretRepositories.vault.properties.credentialProviders";
    public static final String COMMA = ",";
    public static final String DELIMITER = "#";

}
