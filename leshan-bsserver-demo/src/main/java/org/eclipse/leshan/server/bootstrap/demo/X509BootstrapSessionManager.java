package org.eclipse.leshan.server.bootstrap.demo;

import org.eclipse.leshan.core.CertificateUsage;
import org.eclipse.leshan.core.SecurityMode;
import org.eclipse.leshan.core.request.BootstrapRequest;
import org.eclipse.leshan.core.request.Identity;
import org.eclipse.leshan.server.bootstrap.*;
import org.eclipse.leshan.server.security.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

public class X509BootstrapSessionManager extends DefaultBootstrapSessionManager {
    private static final Logger LOG = LoggerFactory.getLogger(X509BootstrapSessionManager.class);

    private final BootstrapSecurityStore bsSecurityStore;
    private final SecurityChecker securityChecker;
    private final JSONFileBootstrapStore bsStore;
    private final X509Certificate autoregServerCert;
    private final CertificateUsage autoregCertificateUsage;
    private final EditableSecurityStore serverSecurityStore;
    private final String autoregBootstrapUri;
    private final String autoregServerUri;

    public X509BootstrapSessionManager(BootstrapSecurityStore bsSecurityStore, JSONFileBootstrapStore bsStore,
            String autoregBootstrapUri, String autoregServerUri, X509Certificate autoregServerCert, CertificateUsage autoregCertificateUsage, EditableSecurityStore serverSecurityStore) {
        this(bsSecurityStore, new SecurityChecker(), bsStore, autoregBootstrapUri, autoregServerUri, autoregServerCert, autoregCertificateUsage, serverSecurityStore);
    }

    public X509BootstrapSessionManager(BootstrapSecurityStore bsSecurityStore, SecurityChecker securityChecker,
            JSONFileBootstrapStore bsStore, String autoregBootstrapUri, String autoregServerUri, X509Certificate autoregServerCert,
            CertificateUsage autoregCertificateUsage, EditableSecurityStore serverSecurityStore) {
        super(bsSecurityStore, securityChecker);
        this.bsStore = bsStore;
        this.securityChecker = securityChecker;
        this.bsSecurityStore = bsSecurityStore;
        this.autoregBootstrapUri = autoregBootstrapUri;
        this.autoregServerUri = autoregServerUri;
        this.autoregServerCert = autoregServerCert;
        this.autoregCertificateUsage = autoregCertificateUsage;
        this.serverSecurityStore = serverSecurityStore;
    }

    @Override
    public BootstrapSession begin(BootstrapRequest request, Identity clientIdentity) {
        boolean authorized;
        if (bsSecurityStore != null) {
            Iterator<SecurityInfo> securityInfos = bsSecurityStore.getAllByEndpoint(request.getEndpointName());

            if (securityInfos == null && clientIdentity.isSecure()) {
                autoRegisterClient(request, clientIdentity);
                securityInfos = bsSecurityStore.getAllByEndpoint(request.getEndpointName());
            }

            authorized = this.securityChecker.checkSecurityInfos(request.getEndpointName(), clientIdentity, securityInfos);
        } else {
            authorized = true;
        }
        DefaultBootstrapSession session = new DefaultBootstrapSession(request, clientIdentity, authorized);
        LOG.trace("Bootstrap session started : {}", session);
        return session;
    }

    private void autoRegisterClient(BootstrapRequest request, Identity clientIdentity) {
        BootstrapConfig bootstrapConfig = new BootstrapConfig();

        bootstrapConfig.toDelete.add("/0");
        bootstrapConfig.toDelete.add("/1");

        BootstrapConfig.ServerConfig serverConfig = new BootstrapConfig.ServerConfig();

        serverConfig.shortId = 1;

        bootstrapConfig.servers.put(0, serverConfig);

        BootstrapConfig.ServerSecurity bsServer = new BootstrapConfig.ServerSecurity();
        bsServer.uri = this.autoregBootstrapUri;
        bsServer.bootstrapServer = true;
        bsServer.securityMode = SecurityMode.EST;
        bsServer.serverId = null;
        bsServer.certificateUsage = CertificateUsage.CA_CONSTRAINT;
        if (autoregServerCert != null) {
            try {
                bsServer.serverPublicKey = autoregServerCert.getEncoded();
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }
        }

        BootstrapConfig.ServerSecurity lwm2mServer = new BootstrapConfig.ServerSecurity();
        lwm2mServer.uri = this.autoregServerUri;
        lwm2mServer.bootstrapServer = false;
        lwm2mServer.securityMode = SecurityMode.EST;
        lwm2mServer.publicKeyOrId = new byte[0];
        lwm2mServer.serverId = 1;
        lwm2mServer.certificateUsage = this.autoregCertificateUsage;
        if (autoregServerCert != null) {
            try {
                lwm2mServer.serverPublicKey = autoregServerCert.getEncoded();
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }
        }
        bootstrapConfig.security.put(0, lwm2mServer);
        bootstrapConfig.security.put(1, bsServer);

        // First save server so that it will be ready
        if (serverSecurityStore != null) {
            try {
                if (serverSecurityStore.getByEndpoint(request.getEndpointName()) == null) {
                    serverSecurityStore.add(SecurityInfo.newESTInfo(request.getEndpointName()));
                }
            } catch (NonUniqueSecurityInfoException e) {
                e.printStackTrace();
            }
        }

        // Then bootstrap config so that we can redirect client
        try {
            bsStore.add(request.getEndpointName(), bootstrapConfig);
        } catch (InvalidConfigurationException e) {
            e.printStackTrace();
        }

    }
}
