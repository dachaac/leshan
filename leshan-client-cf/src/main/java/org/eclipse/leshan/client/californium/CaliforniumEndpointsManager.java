/*******************************************************************************
 * Copyright (c) 2017 Sierra Wireless and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *     Sierra Wireless - initial API and implementation
 *******************************************************************************/
package org.eclipse.leshan.client.californium;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.eclipse.leshan.client.EndpointsManager;
import org.eclipse.leshan.client.servers.ServerIdentity;
import org.eclipse.leshan.client.servers.ServerIdentity.Role;
import org.eclipse.leshan.client.servers.ServerInfo;
import org.eclipse.leshan.core.CertificateUsage;
import org.eclipse.leshan.core.SecurityMode;
import org.eclipse.leshan.core.californium.EndpointContextUtil;
import org.eclipse.leshan.core.californium.EndpointFactory;
import org.eclipse.leshan.core.request.Identity;
import org.eclipse.leshan.core.util.X509CertUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An {@link EndpointsManager} based on Californium(CoAP implementation) and Scandium (DTLS implementation) which
 * supports only 1 server.
 */
public class CaliforniumEndpointsManager implements EndpointsManager {

    private static final Logger LOG = LoggerFactory.getLogger(CaliforniumEndpointsManager.class);

    protected boolean started = false;

    protected ServerIdentity currentServer;
    protected CoapEndpoint currentEndpoint;

    protected Builder dtlsConfigbuilder;
    protected List<Certificate> trustStore;
    protected NetworkConfig coapConfig;
    protected InetSocketAddress localAddress;
    protected CoapServer coapServer;
    protected EndpointFactory endpointFactory;

    public CaliforniumEndpointsManager(InetSocketAddress localAddress, NetworkConfig coapConfig,
            Builder dtlsConfigBuilder, EndpointFactory endpointFactory) {
        this(localAddress, coapConfig, dtlsConfigBuilder, null, endpointFactory);
    }

    /**
     * @since 2.0
     */
    public CaliforniumEndpointsManager(InetSocketAddress localAddress, NetworkConfig coapConfig,
            Builder dtlsConfigBuilder, List<Certificate> trustStore, EndpointFactory endpointFactory) {
        this.localAddress = localAddress;
        this.coapConfig = coapConfig;
        this.dtlsConfigbuilder = dtlsConfigBuilder;
        this.trustStore = trustStore;
        this.endpointFactory = endpointFactory;
    }

    public void setCoapServer(CoapServer coapServer) {
        this.coapServer = coapServer;
    }

    @Override
    public synchronized ServerIdentity createEndpoint(ServerInfo serverInfo) {
        // Clear previous endpoint
        if (currentEndpoint != null) {
            coapServer.getEndpoints().remove(currentEndpoint);
            currentEndpoint.destroy();
        }

        // Create new endpoint
        Identity serverIdentity;
        if (serverInfo.isSecure()) {
            Builder newBuilder = new Builder(dtlsConfigbuilder.getIncompleteConfig());

            // Support PSK
            if (serverInfo.secureMode == SecurityMode.PSK) {
                StaticPskStore staticPskStore = new StaticPskStore(serverInfo.pskId, serverInfo.pskKey);
                newBuilder.setPskStore(staticPskStore);
                serverIdentity = Identity.psk(serverInfo.getAddress(), serverInfo.pskId);
            } else if (serverInfo.secureMode == SecurityMode.RPK) {
                // set identity
                newBuilder.setIdentity(serverInfo.privateKey, serverInfo.publicKey);
                // set RPK truststore
                final PublicKey expectedKey = serverInfo.serverPublicKey;
                newBuilder.setRpkTrustStore(new TrustedRpkStore() {
                    @Override
                    public boolean isTrusted(RawPublicKeyIdentity id) {
                        PublicKey receivedKey = id.getKey();
                        if (receivedKey == null) {
                            LOG.warn("The server public key is null {}", id);
                            return false;
                        }
                        if (!receivedKey.equals(expectedKey)) {
                            LOG.debug(
                                    "Server public key received does match with the expected one.\nReceived: {}\nExpected: {}",
                                    receivedKey, expectedKey);
                            return false;
                        }
                        return true;
                    }
                });
                serverIdentity = Identity.rpk(serverInfo.getAddress(), expectedKey);
            } else if (serverInfo.secureMode == SecurityMode.X509) {
                // set identity
                newBuilder.setIdentity(serverInfo.privateKey, serverInfo.clientCertificateChain);

                // set X509 verifier

                // LWM2M v1.1.1 - 5.2.8.7. Certificate Usage Field
                //
                // 0: Certificate usage 0 ("CA constraint")
                // - trustStore is combination of client's configured trust store and provided certificate in server info
                // - must do PKIX validation with trustStore to build certPath
                // - must check that given certificate is part of certPath
                // - validate server name
                //
                // 1: Certificate usage 1 ("service certificate constraint")
                // - trustStore is client's configured trust store
                // - must do PKIX validation with trustStore
                // - target certificate must match what is provided certificate in server info
                // - validate server name
                //
                // 2: Certificate usage 2 ("trust anchor assertion")
                // - trustStore is only the provided certificate in server info
                // - must do PKIX validation with trustStore
                // - validate server name
                //
                // 3: Certificate usage 3 ("domain-issued certificate") (default mode if missing)
                // - no trustStore used in this mode
                // - target certificate must match what is provided certificate in server info
                // - validate server name

                final CertificateUsage certificateUsage = serverInfo.certificateUsage != null ?
                        serverInfo.certificateUsage :
                        CertificateUsage.DOMAIN_ISSUER_CERTIFICATE;
                final Certificate expectedServerCertificate = serverInfo.serverCertificate;
                X509Certificate[] newTrustedCertificates = null;
                if (certificateUsage == CertificateUsage.CA_CONSTRAINT) {
                    // - trustStore is combination of client's configured trust store and provided certificate in server info
                    ArrayList<X509Certificate> newTrustedCertificatesList = new ArrayList<>(
                            CertPathUtil.toX509CertificatesList(this.trustStore));
                    if (serverInfo.serverCertificate instanceof X509Certificate) {
                        newTrustedCertificatesList.add((X509Certificate) serverInfo.serverCertificate);
                    }
                    newTrustedCertificates = (X509Certificate[]) newTrustedCertificatesList.toArray();
                } else if (certificateUsage == CertificateUsage.SERVICE_CERTIFICATE_CONSTRAINT) {
                    // - trustStore is client's configured trust store
                    newTrustedCertificates = (X509Certificate[]) CertPathUtil.toX509CertificatesList(this.trustStore)
                            .toArray();
                } else if (certificateUsage == CertificateUsage.TRUST_ANCHOR_ASSERTION) {
                    // - trustStore is only the provided certificate in server info
                    if (serverInfo.serverCertificate instanceof X509Certificate) {
                        newTrustedCertificates = new X509Certificate[] {
                                (X509Certificate) serverInfo.serverCertificate };
                    }
                }

                final X509Certificate[] trustedCertificates = newTrustedCertificates;

                newBuilder.setCertificateVerifier(new CertificateVerifier() {

                    @Override
                    public void verifyCertificate(CertificateMessage message, DTLSSession session)
                            throws HandshakeException {
                        CertPath messageChain = message.getCertificateChain();

                        if (messageChain.getCertificates().size() == 0) {
                            AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
                                    session.getPeer());
                            throw new HandshakeException("Certificate chain could not be validated", alert);
                        }

                        Certificate receivedServerCertificate = messageChain.getCertificates().get(0);
                        if (!(receivedServerCertificate instanceof X509Certificate)) {
                            AlertMessage alert = new AlertMessage(AlertLevel.FATAL,
                                    AlertDescription.UNSUPPORTED_CERTIFICATE, session.getPeer());
                            throw new HandshakeException(
                                    "Certificate chain could not be validated - unknown certificate type", alert);
                        }
                        X509Certificate serverCertificate = (X509Certificate) receivedServerCertificate;

                        CertPath certPath = null;
                        if (trustedCertificates != null) {
                            try {
                                // - must do PKIX validation with trustStore
                                certPath = CertPathUtil
                                        .validateCertificatePath(false, messageChain, trustedCertificates);
                            } catch (GeneralSecurityException e) {
                                AlertMessage alert = new AlertMessage(AlertLevel.FATAL,
                                        AlertDescription.BAD_CERTIFICATE, session.getPeer());
                                throw new HandshakeException("Certificate chain could not be validated", alert, e);
                            }
                        }

                        if (certificateUsage == CertificateUsage.CA_CONSTRAINT) {
                            boolean found = false;

                            // - must check that given certificate is part of certPath
                            List<? extends Certificate> certificates = certPath.getCertificates();
                            for (Certificate certificate : certificates) {
                                if (certificate.equals(expectedServerCertificate)) {
                                    found = true;
                                    break;
                                }
                            }

                            if (!found) {
                                // Np match found -> throw exception about it
                                AlertMessage alert = new AlertMessage(AlertLevel.FATAL,
                                        AlertDescription.BAD_CERTIFICATE, session.getPeer());
                                throw new HandshakeException("Certificate chain could not be validated", alert);
                            }
                        } else if ((certificateUsage == CertificateUsage.SERVICE_CERTIFICATE_CONSTRAINT) || (
                                certificateUsage == CertificateUsage.DOMAIN_ISSUER_CERTIFICATE)) {
                            // - target certificate must match what is provided certificate in server info
                            if (!expectedServerCertificate.equals(serverCertificate)) {
                                AlertMessage alert = new AlertMessage(AlertLevel.FATAL,
                                        AlertDescription.BAD_CERTIFICATE, session.getPeer());
                                throw new HandshakeException("Certificate chain could not be validated", alert);
                            }
                        } else if (certificateUsage == CertificateUsage.TRUST_ANCHOR_ASSERTION) {
                            // Nothing extra to check
                        } else {
                            // Not supported certificate usage
                            AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
                                    session.getPeer());
                            throw new HandshakeException(
                                    "Certificate chain could not be validated - not supported certificate usage",
                                    alert);
                        }

                        // - validate server name
                        validateSubject(session, serverCertificate);
                    }

                    private void validateSubject(final DTLSSession session,
                            final X509Certificate receivedServerCertificate) throws HandshakeException {
                        final InetSocketAddress peerSocket = session.getPeer();

                        if (X509CertUtil.matchSubjectDnsName(receivedServerCertificate, peerSocket.getHostName()))
                            return;

                        if (X509CertUtil.matchSubjectInetAddress(receivedServerCertificate, peerSocket.getAddress()))
                            return;

                        AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
                                session.getPeer());
                        throw new HandshakeException(
                                "Certificate chain could not be validated - server identity does not match certificate",
                                alert);
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                });
                serverIdentity = Identity.x509(serverInfo.getAddress(), EndpointContextUtil
                        .extractCN(((X509Certificate) expectedServerCertificate).getSubjectX500Principal().getName()));
            } else {
                throw new RuntimeException("Unable to create connector : unsupported security mode");
            }
            currentEndpoint = endpointFactory.createSecuredEndpoint(newBuilder.build(), coapConfig, null);
        } else {
            currentEndpoint = endpointFactory.createUnsecuredEndpoint(localAddress, coapConfig, null);
            serverIdentity = Identity.unsecure(serverInfo.getAddress());
        }

        // Add new endpoint
        coapServer.addEndpoint(currentEndpoint);

        // Start endpoint if needed
        if (serverInfo.bootstrap) {
            currentServer = new ServerIdentity(serverIdentity, serverInfo.serverId, Role.LWM2M_BOOTSTRAP_SERVER);
        } else {
            currentServer = new ServerIdentity(serverIdentity, serverInfo.serverId);
        }
        if (started) {
            coapServer.start();
            try {
                currentEndpoint.start();
                LOG.info("New endpoint created for server {} at {}", currentServer.getUri(), currentEndpoint.getUri());
            } catch (IOException e) {
                throw new RuntimeException("Unable to start endpoint", e);
            }
        }
        return currentServer;
    }

    @Override
    public synchronized Collection<ServerIdentity> createEndpoints(Collection<? extends ServerInfo> serverInfo) {
        if (serverInfo == null || serverInfo.isEmpty())
            return null;
        else {
            // TODO support multi server
            if (serverInfo.size() > 1) {
                LOG.warn(
                        "CaliforniumEndpointsManager support only connection to 1 LWM2M server, first server will be used from the server list of {}",
                        serverInfo.size());
            }
            ServerInfo firstServer = serverInfo.iterator().next();
            Collection<ServerIdentity> servers = new ArrayList<>(1);
            servers.add(createEndpoint(firstServer));
            return servers;
        }
    }

    @Override
    public long getMaxCommunicationPeriodFor(ServerIdentity server, long lifetimeInMs) {
        // See https://github.com/OpenMobileAlliance/OMA_LwM2M_for_Developers/issues/283 to better understand.
        // TODO For DTLS, worst Handshake scenario should be taking into account too.

        int floor = 30000; // value from which we stop to adjust communication period using COAP EXCHANGE LIFETIME.

        // To be sure registration doesn't expired, update request should be send considering all CoAP retransmissions
        // and registration lifetime.
        // See https://tools.ietf.org/html/rfc7252#section-4.8.2
        long exchange_lifetime = coapConfig.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, 247);
        if (lifetimeInMs - exchange_lifetime >= floor) {
            return lifetimeInMs - exchange_lifetime;
        } else {
            LOG.warn("Too small lifetime : we advice to not use a lifetime < (COAP EXCHANGE LIFETIME + 30s)");
            // lifetime value is too short, so we do a compromise and we don't remove COAP EXCHANGE LIFETIME completely
            // We distribute the remaining lifetime range [0, exchange_lifetime + floor] on the remaining range
            // [1,floor]s.
            return lifetimeInMs * (floor - 1000) / (exchange_lifetime + floor) + 1000;
        }
    }

    @Override
    public synchronized void forceReconnection(ServerIdentity server, boolean resume) {
        // TODO support multi server
        if (server == null || !server.equals(currentServer))
            return;

        Connector connector = currentEndpoint.getConnector();
        if (connector instanceof DTLSConnector) {
            if (resume) {
                LOG.info("Clear DTLS session for resumption for server {}", server.getUri());
                ((DTLSConnector) connector).forceResumeAllSessions();
            } else {
                LOG.info("Clear DTLS session for server {}", server.getUri());
                ((DTLSConnector) connector).clearConnectionState();
            }
        }

    }

    public synchronized Endpoint getEndpoint(ServerIdentity server) {
        // TODO support multi server
        if (server != null && server.equals(currentServer) && currentEndpoint.isStarted())
            return currentEndpoint;
        return null;
    }

    @Override
    public synchronized void start() {
        if (started)
            return;
        started = true;

        // we don't have any endpoint so nothing to start
        if (currentEndpoint == null)
            return;

        coapServer.start();
    }

    @Override
    public synchronized void stop() {
        if (!started)
            return;
        started = false;

        // If we have no endpoint this means that we never start coap server
        if (currentEndpoint == null)
            return;

        coapServer.stop();
    }

    @Override
    public synchronized void destroy() {
        if (started)
            started = false;

        coapServer.destroy();
    }
}
