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

package org.wso2.carbon.securevault.aws.common;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.aws.exception.AWSVaultException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProviderChain;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.AWS_REGION_PARAMETER;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.COMMA;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.CREDENTIAL_PROVIDERS;

/**
 * Provides an instance of the secrets client that connects to the AWS Secrets Manager.
 */
public class AWSSecretManagerClient {

    private static final Log log = LogFactory.getLog(AWSSecretManagerClient.class);

    private static volatile SecretsManagerClient secretsClient;

    private AWSSecretManagerClient() {

    }

    /**
     * Get the instance of the AWS SecretsManagerClient.
     * If one has not yet been created, the method will create a client and return it.
     *
     * @param properties Configuration properties.
     * @return AWS Secrets Manager Client instance.
     */
    public static SecretsManagerClient getInstance(Properties properties) {

        if (secretsClient == null) {
            synchronized (AWSSecretManagerClient.class) {
                if (secretsClient == null) {
                    Region region = getAWSRegion(properties);
                    AwsCredentialsProvider credentialsProvider = getCredentialsProvider(properties);
                    secretsClient = SecretsManagerClient.builder()
                            .region(region)
                            .credentialsProvider(credentialsProvider)
                            .build();
                    log.info("AWS Secrets Client created.");
                }
            }
        }
        return secretsClient;
    }

    /**
     * Method to get the AWS Region from the properties file.
     *
     * @param properties Configuration properties.
     * @return The AWS Region.
     * @throws AWSVaultException If the AWS Region is not set in the properties file or if it is invalid.
     */
    private static Region getAWSRegion(Properties properties) throws AWSVaultException {

        String regionString = properties.getProperty(AWS_REGION_PARAMETER);
        if (StringUtils.isEmpty(regionString)) {
            throw new AWSVaultException("AWS Region has not been set in secret-conf.properties file. "
                    + "Cannot build AWS Secrets Client! ");
        }
        Region region = Region.of(regionString);
        if (!Region.regions().contains(region)) {
            throw new AWSVaultException("AWS Region specified is invalid. Cannot build AWS Secrets Client! ");
        }
        return region;
    }

    /**
     * Method to get the AWS Credential Provider Chain based on the configuration in the config file.
     * If new credential provider types are needed to be added, add a new mapping in the switch statement.
     *
     * @param properties Configuration properties.
     * @return AwsCredentialsProvider.
     * @throws AWSVaultException If the provider types are not specified or invalid.
     */
    private static AwsCredentialsProvider getCredentialsProvider(Properties properties) throws AWSVaultException {

        List<AwsCredentialsProvider> awsCredentialsProviders = new ArrayList<>();
        String credentialProvidersString = properties.getProperty(CREDENTIAL_PROVIDERS);
        String[] credentialProviderTypes;

        if (StringUtils.isNotEmpty(credentialProvidersString)) {
            if (credentialProvidersString.contains(COMMA)) {
                credentialProviderTypes = credentialProvidersString.split(COMMA);
            } else {
                credentialProviderTypes = new String[]{credentialProvidersString};
            }

            for (String credentialType : credentialProviderTypes) {
                switch (credentialType) {
                    case "env":
                        awsCredentialsProviders.add(EnvironmentVariableCredentialsProvider.create());
                        break;
                    case "ec2":
                        awsCredentialsProviders.add(InstanceProfileCredentialsProvider.create());
                        break;
                    case "ecs":
                        awsCredentialsProviders.add(ContainerCredentialsProvider.builder().build());
                        break;
                    case "default":
                        awsCredentialsProviders.add(DefaultCredentialsProvider.create());
                        break;
                    default:
                        throw new AWSVaultException("Credential provider type " + credentialType + " is invalid. ");
                }
            }

        } else {
            throw new AWSVaultException("AWS Credential provider type not given in configuration file. ");
        }

        return AwsCredentialsProviderChain.builder().credentialsProviders(awsCredentialsProviders).build();
    }
}
