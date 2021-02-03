/*
 *  Copyright (C) 2021 Tirasa (info@tirasa.net)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.tirasa.cieid;

import org.apache.commons.lang.StringUtils;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.core.authentication.PersonDirectoryPrincipalResolverProperties;
import org.apereo.cas.configuration.model.support.x509.X509Properties;
import org.apereo.services.persondir.IPersonAttributeDao;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CIEIDServerConfiguration {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("attributeRepository")
    private ObjectProvider<IPersonAttributeDao> attributeRepository;

    @Autowired
    private PrincipalFactory x509PrincipalFactory;

    @Bean
    @RefreshScope
    public PrincipalResolver x509SubjectDNPrincipalResolver() {
        X509Properties x509 = casProperties.getAuthn().getX509();
        PersonDirectoryPrincipalResolverProperties personDirectory = casProperties.getPersonDirectory();
        PersonDirectoryPrincipalResolverProperties principal = x509.getPrincipal();
        String principalAttribute = StringUtils.defaultIfBlank(
                principal.getPrincipalAttribute(), personDirectory.getPrincipalAttribute());
        return new CIEIDX509SubjectDNPrincipalResolver(
                attributeRepository.getObject(),
                x509PrincipalFactory,
                principal.isReturnNull() || personDirectory.isReturnNull(),
                principalAttribute,
                principal.isUseExistingPrincipalId() || personDirectory.isUseExistingPrincipalId(),
                principal.isAttributeResolutionEnabled(),
                org.springframework.util.StringUtils.commaDelimitedListToSet(
                        principal.getActiveAttributeRepositoryIds()));
    }
}
