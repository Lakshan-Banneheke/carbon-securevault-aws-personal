package org.wso2.carbon.securevault.aws;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.wso2.carbon.securevault.aws.AWSVaultConstants.AWS_REGION_PARAMETER;
import static org.wso2.carbon.securevault.aws.AWSVaultConstants.CREDENTIAL_PROVIDERS;

public class AWSSecretManagerClient {
    private static final Log log = LogFactory.getLog(AWSSecretManagerClient.class);

    private static SecretsManagerClient secretsClient;

    public static SecretsManagerClient getInstance(Properties properties){
        if (secretsClient==null){
            synchronized (AWSSecretManagerClient.class){
                if (secretsClient==null){
                    try {
                        log.info("Initializing AWS Secure Vault");
                        Region region = getAWSRegion(properties);
                        AwsCredentialsProvider credentialsProvider = getCredentialsProvider(properties);
                        secretsClient = SecretsManagerClient.builder()
                                .region(region)
                                .credentialsProvider(credentialsProvider)
                                .build();
                        log.info("AWS Secrets Client created");

                    } catch (AWSVaultException e) {
                        log.error(e.getMessage(), e);
                    }
                }
            }
        }
        return secretsClient;
    }

    /**
     * Method to get the AWS Region from the properties file.
     *
     * @param properties Configuration properties
     * @return The AWS Region
     * @throws AWSVaultException if the AWS Region is not set in the properties file or if it is invalid.
     */
    private static Region getAWSRegion(Properties properties) throws AWSVaultException{
        String regionString = properties.getProperty(AWS_REGION_PARAMETER);
        if (StringUtils.isEmpty(regionString)) {
            throw new AWSVaultException("AWS Region has not been set in secret-conf.properties file. Cannot build AWS Secrets Client!");
        }
        Region region = Region.of(regionString);
        if (!Region.regions().contains(region)){
            throw new AWSVaultException("AWS Region specified is invalid. Cannot build AWS Secrets Client!");
        }
        return region;
    }

    /**
     * Method to get the AWS Credential Provider Chain based on the configuration in the config file.
     *
     * @param properties Configuration properties
     * @return AwsCredentialsProvider
     * @throws AWSVaultException if the provider types are not specified or invalid.
     */
    private static AwsCredentialsProvider getCredentialsProvider(Properties properties) throws AWSVaultException {
        List<AwsCredentialsProvider> awsCredentialsProviders = new ArrayList<>();

        String credentialProvidersString = properties.getProperty(CREDENTIAL_PROVIDERS);

        if (StringUtils.isNotEmpty(credentialProvidersString)) {

            String[] credentialProviderTypes;
            if (credentialProvidersString.contains(",")) {
                credentialProviderTypes = credentialProvidersString.split(",");
            } else {
                credentialProviderTypes = new String[]{credentialProvidersString};
            }

            for (String credentialType : credentialProviderTypes) {
             //If new credential provider types are needed to be added, add a new mapping in the switch statement
                switch (credentialType) {
                    case "env":
                        awsCredentialsProviders.add(EnvironmentVariableCredentialsProvider.create());
                        break;
                    case "ec2":
                        awsCredentialsProviders.add(InstanceProfileCredentialsProvider.create());
                        break;
                    case "ecs":
                        awsCredentialsProviders.add(ContainerCredentialsProvider.builder().build());
                    case "default":
                        awsCredentialsProviders.add(DefaultCredentialsProvider.create());
                }
            }
            if (awsCredentialsProviders.isEmpty()){
                throw new AWSVaultException("All AWS credential providers specified in the configuration file are invalid.");
            }

        } else {
            throw new AWSVaultException("AWS Credential provider type not given in configuration file.");
        }

        return AwsCredentialsProviderChain.builder().credentialsProviders(awsCredentialsProviders).build();
    }
}
