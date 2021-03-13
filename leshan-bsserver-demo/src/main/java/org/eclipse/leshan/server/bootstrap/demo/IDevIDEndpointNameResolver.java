package org.eclipse.leshan.server.bootstrap.demo;

import org.eclipse.leshan.core.util.EndpointNameResolver;
import org.eclipse.leshan.core.util.X509CertUtil;

import java.security.Principal;
import java.security.cert.X509Certificate;

public class IDevIDEndpointNameResolver implements EndpointNameResolver {

    private final int enterpriseId;

    public IDevIDEndpointNameResolver(int enterpriseId) {
        this.enterpriseId = enterpriseId;
    }

    @Override
    public String resolve(X509Certificate[] certificateChain) {
        Principal subjectDN = certificateChain[0].getSubjectX500Principal();

        String cn = X509CertUtil.getPrincipalField(subjectDN, "CN");
        String serialNumber = X509CertUtil.getPrincipalField(subjectDN, "SERIALNUMBER");

        if (cn == null || serialNumber == null)
            return null;

        return "urn:dev:ops:" + this.enterpriseId + "-" + cn + "-" + serialNumber;
    }
}
