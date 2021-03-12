package org.eclipse.leshan.client.demo;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.eclipse.leshan.client.est.EstClientOperations;
import org.eclipse.leshan.client.est.EstDeviceSettings;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class EstClientOperationsImpl implements EstClientOperations {
    private EstDeviceSettings estDeviceSettings;

    @Override
    public void persistEstDeviceSettings(EstDeviceSettings estDeviceSettings) {
        System.out.println("Persisting EST device settings");
        this.estDeviceSettings = estDeviceSettings;
    }

    @Override
    public byte[] generateCertificateSigningRequest(X509Certificate clientCertificate, PrivateKey privateKey) throws Exception {
        PKCS10CertificationRequestBuilder p10Builder
                = new JcaPKCS10CertificationRequestBuilder(
                clientCertificate.getSubjectX500Principal(), clientCertificate.getPublicKey());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(clientCertificate.getSigAlgName());
        ContentSigner signer = csBuilder.build(privateKey);
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        return csr.getEncoded();
    }
}
