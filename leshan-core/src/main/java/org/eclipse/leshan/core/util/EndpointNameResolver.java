package org.eclipse.leshan.core.util;

import java.security.cert.X509Certificate;

public interface EndpointNameResolver {
    String resolve(X509Certificate[] certificateChain);
}
