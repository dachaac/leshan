package org.eclipse.leshan.server.bootstrap.demo.est;

import java.net.URI;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

public class EstRegistrarConfig {
    public URI estBaseUri;

    public String username;
    public String password;

    public List<Certificate> trustStore;
    public X509Certificate[] estClientCertificate;
    public PrivateKey estClientPrivateKey;
}
