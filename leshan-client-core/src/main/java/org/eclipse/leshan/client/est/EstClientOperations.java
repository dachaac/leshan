package org.eclipse.leshan.client.est;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface EstClientOperations {
    void persistEstDeviceSettings(EstDeviceSettings estDeviceSettings);

    byte[] generateCertificateSigningRequest(X509Certificate clientCertificate, PrivateKey privateKey) throws Exception;
}
