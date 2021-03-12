package org.eclipse.leshan.server.bootstrap.demo.est;

import org.apache.commons.codec.binary.Base64;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.auth.BasicScheme;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.ssl.HttpsSupport;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.ssl.TrustStrategy;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.leshan.server.est.CoapEstHandler;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CoapEstRegistrarHandler implements CoapEstHandler {
    private final CloseableHttpClient httpClient;

    private BasicScheme estBasicAuth = null;

    private final URI estCaCertsUri;
    private final URI estCsrAttributesUri;
    private final URI estSimpleEnrollUri;
    private final URI estSimpleReEnrollUri;

    final byte[] beginCsrPem = "-----BEGIN CERTIFICATE REQUEST-----\r\n".getBytes(StandardCharsets.UTF_8);
    final byte[] endCsrPem = "-----END CERTIFICATE REQUEST-----\r\n".getBytes(StandardCharsets.UTF_8);
    public static final ContentType contentTypeApplicationPkcs10 = ContentType.create("application/pkcs10");

    public CoapEstRegistrarHandler(EstRegistrarConfig estRegistrarConfig)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException,
            KeyManagementException, UnrecoverableKeyException {
        this.httpClient = getHttpClient(estRegistrarConfig);

        if (estRegistrarConfig.username != null) {
            this.estBasicAuth = new BasicScheme();
            this.estBasicAuth.initPreemptive(new UsernamePasswordCredentials(estRegistrarConfig.username, estRegistrarConfig.password.toCharArray()));
        }

        this.estCaCertsUri = estRegistrarConfig.estBaseUri.resolve("cacerts");
        this.estCsrAttributesUri = estRegistrarConfig.estBaseUri.resolve("csrattrs");
        this.estSimpleEnrollUri = estRegistrarConfig.estBaseUri.resolve("simpleenroll");
        this.estSimpleReEnrollUri = estRegistrarConfig.estBaseUri.resolve("simplereenroll");
    }

    private static CloseableHttpClient getHttpClient(EstRegistrarConfig estRegistrarConfig)
            throws NoSuchAlgorithmException, KeyManagementException, CertificateException, KeyStoreException,
            IOException, UnrecoverableKeyException {
        // Trust own CA and all self-signed certs
        SSLContextBuilder ssllContextBuilder = SSLContexts.custom();

        if (estRegistrarConfig.trustStore != null) {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null);
            for (java.security.cert.Certificate certificate : estRegistrarConfig.trustStore) {
                String alias = certificate.toString();
                trustStore.setCertificateEntry(alias, certificate);
            }

            ssllContextBuilder.loadTrustMaterial(trustStore, new TrustStrategy() {
                @Override
                public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    // Use trust store implicitly
                    return false;
                }
            });
        } else {
            ssllContextBuilder.loadTrustMaterial(new TrustAllStrategy());
        }

        if (estRegistrarConfig.estClientCertificate != null) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            keyStore.setKeyEntry("est-server", estRegistrarConfig.estClientPrivateKey, null, estRegistrarConfig.estClientCertificate);
            ssllContextBuilder.loadKeyMaterial(keyStore, null);
        }

        SSLContext sslcontext = ssllContextBuilder.build();

        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslcontext,
                null,
                null,
                HttpsSupport.getDefaultHostnameVerifier());

        final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslSocketFactory)
                .build();

        HttpClientBuilder builder = HttpClients.custom();

        if (estRegistrarConfig.username != null) {
            BasicCredentialsProvider credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(
                    new AuthScope(HttpHost.create(estRegistrarConfig.estBaseUri)),
                    new UsernamePasswordCredentials(estRegistrarConfig.username, estRegistrarConfig.password.toCharArray()));

            builder.setDefaultCredentialsProvider(credsProvider);
        }

        builder.setConnectionManager(cm);

        return builder.build();
    }

    @Override
    public byte[] getCaCerts(InetSocketAddress peerAddress, Principal senderIdentity) throws Exception {
        HttpGet request = new HttpGet(this.estCaCertsUri);

        try (CloseableHttpResponse response = this.httpClient.execute(request)) {

            // If successful, the server response MUST have an HTTP 200 response
            // code.  Any other response code indicates an error and the client MUST
            // abort the protocol.
            int statusCode = response.getCode();
            if (statusCode != 200) {
                throw new Exception("Failed to fetch cacerts. HTTP Status Code: " + statusCode);
            }

            HttpEntity entity = response.getEntity();
            byte[] data = EntityUtils.toByteArray(entity);
            EntityUtils.consume(entity);

            return Base64.decodeBase64(data);
        }
    }

    @Override
    public byte[] getCsrAttrs(InetSocketAddress peerAddress, Principal senderIdentity) throws Exception {
        HttpGet request = new HttpGet(this.estCsrAttributesUri);

        try (CloseableHttpResponse response = this.httpClient.execute(request)) {

            // If successful, the server response MUST have an HTTP 200 response
            // code.  Any other response code indicates an error and the client MUST
            // abort the protocol.
            int statusCode = response.getCode();
            if (statusCode != 200) {
                throw new Exception("Failed to fetch cacerts. HTTP Status Code: " + statusCode);
            }

            HttpEntity entity = response.getEntity();
            byte[] data = EntityUtils.toByteArray(entity);
            EntityUtils.consume(entity);

            return Base64.decodeBase64(data);
        }
    }

    @Override
    public byte[] simpleEnroll(InetSocketAddress peerAddress, Principal senderIdentity, int requestAccept,
            int requestContentFormat, byte[] requestPayload) throws Exception {
        if (requestAccept != 281 && requestAccept != -1) {
            throw new Exception("Unsupported accepted content format: " + requestAccept);
        }

        if (requestContentFormat != 286) {
            throw new Exception("Unsupported request content format: " + requestContentFormat);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(beginCsrPem);
        baos.write(Base64.encodeBase64(requestPayload, true));
        baos.write(endCsrPem);

        byte[] estPayload = baos.toByteArray();

        HttpPost request = new HttpPost(this.estSimpleEnrollUri);
        request.setEntity(new ByteArrayEntity(estPayload, contentTypeApplicationPkcs10));

        final HttpClientContext localContext = HttpClientContext.create();
        localContext.resetAuthExchange(HttpHost.create(this.estSimpleEnrollUri), this.estBasicAuth);

        try (CloseableHttpResponse response = this.httpClient.execute(request, localContext)) {
            // If the enrollment is successful, the server response MUST contain an
            // HTTP 200 response code with a content-type of
            // "application/pkcs7-mime".
            //
            // The server MUST answer with a suitable 4xx or 5xx HTTP [RFC2616]
            // error code when a problem occurs.
            //
            // If the server responds with an HTTP [RFC2616] 202, this indicates
            // that the request has been accepted for processing but that a response
            // is not yet available.  The server MUST include a Retry-After header
            // as defined for HTTP 503 responses.
            int statusCode = response.getCode();
            if (statusCode != 200) {
                throw new Exception("Failed simple enroll for certificate.");
            }

            HttpEntity entity = response.getEntity();

            byte [] data = EntityUtils.toByteArray(entity);
            EntityUtils.consume(entity);

            return Base64.decodeBase64(data);
        }
    }

    @Override
    public byte[] simpleReEnroll(InetSocketAddress peerAddress, Principal senderIdentity, int requestAccept,
            int requestContentFormat, byte[] requestPayload) throws Exception {
        if (requestAccept != 281 && requestAccept != -1) {
            throw new Exception("Unsupported accepted content format: " + requestAccept);
        }

        if (requestContentFormat != 286) {
            throw new Exception("Unsupported request content format: " + requestContentFormat);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(beginCsrPem);
        baos.write(Base64.encodeBase64(requestPayload, true));
        baos.write(endCsrPem);

        byte[] estPayload = baos.toByteArray();

        HttpPost request = new HttpPost(this.estSimpleReEnrollUri);
        request.setEntity(new ByteArrayEntity(estPayload, contentTypeApplicationPkcs10));

        final HttpClientContext localContext = HttpClientContext.create();
        localContext.resetAuthExchange(HttpHost.create(this.estSimpleReEnrollUri), this.estBasicAuth);

        try (CloseableHttpResponse response = this.httpClient.execute(request, localContext)) {
            // If the enrollment is successful, the server response MUST contain an
            // HTTP 200 response code with a content-type of
            // "application/pkcs7-mime".
            //
            // The server MUST answer with a suitable 4xx or 5xx HTTP [RFC2616]
            // error code when a problem occurs.
            //
            // If the server responds with an HTTP [RFC2616] 202, this indicates
            // that the request has been accepted for processing but that a response
            // is not yet available.  The server MUST include a Retry-After header
            // as defined for HTTP 503 responses.
            int statusCode = response.getCode();
            if (statusCode != 200) {
                throw new Exception("Failed simple enroll for certificate.");
            }

            HttpEntity entity = response.getEntity();

            byte [] data = EntityUtils.toByteArray(entity);
            EntityUtils.consume(entity);

            return Base64.decodeBase64(data);
        }
    }
}
