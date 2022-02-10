package org.wso2.carbon.securevault.aws;

import org.apache.commons.lang.StringUtils;
import software.amazon.awssdk.regions.Region;

import java.util.Properties;

import static org.wso2.carbon.securevault.aws.AWSVaultConstants.AWS_REGION_PARAMETER;

public class AWSVaultUtils {
    /**
     * Util method to get the AWS Region from the properties file.
     *
     * @param properties Configuration properties
     * @return The AWS Region
     * @throws AWSVaultException if the AWS Region is not set in the properties file or if it is invalid.
     */
    public static Region getAWSRegion(Properties properties) throws AWSVaultException{
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
