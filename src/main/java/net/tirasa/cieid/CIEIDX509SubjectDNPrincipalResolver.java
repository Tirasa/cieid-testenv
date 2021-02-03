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

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.adaptors.x509.authentication.principal.AbstractX509PrincipalResolver;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.services.persondir.IPersonAttributeDao;

public class CIEIDX509SubjectDNPrincipalResolver extends AbstractX509PrincipalResolver {

    private static final SecureRandom RND = new SecureRandom();

    private static String randomBirthDate() {
        return RND.ints(1930, 2010).findFirst().getAsInt()
                + "-" + String.format("%02d", RND.ints(1, 12).findFirst().getAsInt())
                + "-" + String.format("%02d", RND.ints(1, 28).findFirst().getAsInt());
    }

    public CIEIDX509SubjectDNPrincipalResolver(
            final IPersonAttributeDao attributeRepository,
            final PrincipalFactory principalFactory,
            final boolean returnNullIfNoAttributes,
            final String principalAttributeName,
            final boolean useCurrentPrincipalId,
            final boolean resolveAttributes,
            final Set<String> activeAttributeRepositoryIdentifiers) {

        super(attributeRepository,
                principalFactory,
                returnNullIfNoAttributes,
                principalAttributeName,
                useCurrentPrincipalId,
                resolveAttributes,
                activeAttributeRepositoryIdentifiers);
    }

    @Override
    protected Map<String, List<Object>> extractPersonAttributes(final X509Certificate certificate) {
        Map<String, List<Object>> attributes = super.extractPersonAttributes(certificate);

        String subjectDN = certificate.getSubjectDN().getName();
        org.springframework.util.StringUtils.commaDelimitedListToSet(subjectDN).stream().
                map(e -> e.split("=")).
                forEach(e -> attributes.put(e[0].trim(), List.of(e[1].trim())));
        attributes.put("DATE_OF_BIRTH", List.of(randomBirthDate()));
        attributes.put("CF", List.of(resolvePrincipalInternal(certificate)));

        return attributes;
    }

    @Override
    protected String resolvePrincipalInternal(final X509Certificate certificate) {
        String subjectDN = certificate.getSubjectDN().getName();
        Map<String, String> attributes =
                org.springframework.util.StringUtils.commaDelimitedListToSet(subjectDN).stream().
                        map(e -> e.split("=")).
                        collect(Collectors.toMap(e -> e[0].trim(), e -> e[1].trim()));
        return Optional.ofNullable(attributes.get("CN")).
                map(cn -> "TINIT-" + StringUtils.substringBefore(cn, "/")).
                orElse(subjectDN);
    }
}
