package org.wso2.carbon.securevault.aws;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

import java.util.Properties;

import static org.wso2.carbon.securevault.aws.AWSVaultConstants.AWS_REGION_PARAMETER;

public class AWSSecretManagerClient {
    private static final Log log = LogFactory.getLog(AWSSecretManagerClient.class);

    private static SecretsManagerClient secretsClient;

    private AWSSecretManagerClient(Properties properties){

    }

    public static SecretsManagerClient getInstance(Properties properties){
        if (secretsClient==null){
            synchronized (AWSSecretManagerClient.class){
                if (secretsClient==null){
                    try {
                        Region region = getAWSRegion(properties);
                        secretsClient = SecretsManagerClient.builder()
                                .region(region)
                                .build();

                    } catch (AWSVaultException e) {
                        log.error(e.getMessage(), e);
                    }
                }
            }
        }
        return secretsClient;
    }

    /**
     * Util method to get the AWS Region from the properties file.
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
}
