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

import java.util.Properties;

import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.LEGACY_PROPERTIES_PATH;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.NOVEL_PROPERTIES_PATH;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.REGEX;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.SECRET_REPOSITORIES;

/**
 * Util methods used in the AWS Vault extension.
 */
public class AWSVaultUtils {

    private AWSVaultUtils() {

    }

    private static final Log log = LogFactory.getLog(AWSVaultUtils.class);

    /**
     * Util method to get the properties based on legacy or novel method used for defining the property
     * in the configurations file.
     *
     * @param properties   Configuration properties.
     * @param propertyName Name of the required property.
     * @return Properties Key.
     */
    public static String getProperty(Properties properties, String propertyName) {
        String propKey = getPropKey(properties, propertyName);
        String property = properties.getProperty(propKey);
        if (StringUtils.isEmpty(property)) {
            throw new AWSVaultException("Property " + propertyName.replaceAll(REGEX, "") +
                    " has not been set in secret-conf.properties file. Cannot build AWS Secrets Client! ");
        }
        return property;
    }

    public static String getProperty(Properties properties, String propertyName, String defaultValue) {
        String propKey = getPropKey(properties, propertyName);
        String property = properties.getProperty(propKey);
        if (StringUtils.isEmpty(property)) {
            return defaultValue;
        }
        return property;
    }

    private static String getPropKey(Properties properties, String propertyName) {

        String propKey;
        boolean novelFlag = StringUtils.isEmpty(properties.getProperty(SECRET_REPOSITORIES, null));
        if (novelFlag) {
            if (log.isDebugEnabled()) {
                log.debug("Properties specified in the novel method.");
            }
            propKey = NOVEL_PROPERTIES_PATH + propertyName;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Properties specified in the legacy method.");
            }
            propKey = LEGACY_PROPERTIES_PATH + propertyName;
        }
        return propKey;
    }
}
