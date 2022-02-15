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
        return new AWSSecretRepository();
    }
}
