package org.eclipse.leshan.core.util;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class EndpointNameUtil {
    public static Map<String, EndpointNameResolver> resolvers = new HashMap<String, EndpointNameResolver>();

    public static String resolve(X509Certificate[] certificateChain) {
        String rootCAName = null;

        if (certificateChain.length > 1) {
            X509Certificate rootCA = certificateChain[certificateChain.length - 1];

            rootCAName = rootCA.getSubjectDN().getName();
        }

        if (resolvers.containsKey(rootCAName)) {
            EndpointNameResolver resolver = resolvers.get(rootCAName);
            return resolver.resolve(certificateChain);
        } else {
            return X509CertUtil.getPrincipalField(certificateChain[0].getSubjectX500Principal(), "CN");
        }
    }
}
