package org.eclipse.leshan.client.demo;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.eclipse.leshan.client.est.EstClientOperations;
import org.eclipse.leshan.client.est.EstDeviceSettings;

import javax.security.auth.x500.X500Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class EstClientOperationsImpl implements EstClientOperations {
    private EstDeviceSettings estDeviceSettings;
    private String endpointName;

    public EstClientOperationsImpl(String endpointName) {
        this.endpointName = endpointName;
    }

    @Override
    public void persistEstDeviceSettings(EstDeviceSettings estDeviceSettings) {
        System.out.println("Persisting EST device settings");
        this.estDeviceSettings = estDeviceSettings;
    }

    @Override
    public byte[] generateCertificateSigningRequest(X509Certificate clientCertificate, PrivateKey privateKey) throws Exception {
        X500Principal subjectDN = new X500Principal("CN=" + endpointName);
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subjectDN,
                clientCertificate.getPublicKey());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(clientCertificate.getSigAlgName());
        ContentSigner signer = csBuilder.build(privateKey);
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        return csr.getEncoded();
    }
}
