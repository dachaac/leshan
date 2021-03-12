/*******************************************************************************
 * Copyright (c) 2013-2015 Sierra Wireless and others.
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
package org.eclipse.leshan.server.security;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

import org.eclipse.leshan.core.util.Validate;

/**
 * The security info for a client.
 * <p>
 * A {@link SecurityInfo} contain data about how a client should authenticate itself.
 * <p>
 * The following security modes are supported:
 * <ul>
 * <li>Pre-Shared Key: the given identity and a key are needed</li>
 * <li>Raw Public Key Certificate: the given public key is needed</li>
 * <li>X509 Certificate: any trusted X509 certificate is needed</li>
 * </ul>
 */
public class SecurityInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    // the client end-point
    private final String endpoint;

    // PSK
    private final String identity;
    private final byte[] preSharedKey;

    // RPK
    private final PublicKey rawPublicKey;

    // X.509
    private final boolean useX509Cert;

    // EST
    private final boolean useEST;

    private SecurityInfo(String endpoint, String identity, byte[] preSharedKey, PublicKey rawPublicKey,
            boolean useX509Cert, boolean useEST) {
        Validate.notEmpty(endpoint);
        this.endpoint = endpoint;
        this.identity = identity;
        this.preSharedKey = preSharedKey;
        this.rawPublicKey = rawPublicKey;
        this.useX509Cert = useX509Cert;
        this.useEST = useEST;
    }

    /**
     * Construct a {@link SecurityInfo} meaning that client with given endpoint name should authenticate itself using
     * PSK mode and the given PSK Identity and the given Pre-Shared Key.
     * 
     * @param endpoint the endpont name of the client.
     * @param identity the expected PSK Identity.
     * @param preSharedKey the expected Pre-Shared Key.
     * @return a PSK Security Info.
     */
    public static SecurityInfo newPreSharedKeyInfo(String endpoint, String identity, byte[] preSharedKey) {
        Validate.notEmpty(identity);
        Validate.notNull(preSharedKey);
        return new SecurityInfo(endpoint, identity, preSharedKey, null, false, false);
    }

    /**
     * Construct a {@link SecurityInfo} meaning that client with given endpoint name should authenticate itself using
     * RPK mode and the given Raw Public Key.
     * 
     * @param endpoint the endpont name of the client.
     * @param rawPublicKey the expected Raw Public Key.
     * @return a RPK Security Info.
     */
    public static SecurityInfo newRawPublicKeyInfo(String endpoint, PublicKey rawPublicKey) {
        Validate.notNull(rawPublicKey);
        return new SecurityInfo(endpoint, null, null, rawPublicKey, false, false);
    }

    /**
     * Construct a {@link SecurityInfo} meaning that client with given endpoint name should authenticate itself using
     * X.509 mode with any trusted X.509 Certificate.
     * <p>
     * By default, the certificate Common Name (CN) MUST match the endpoint name.
     * 
     * @param endpoint the endpont name of the client.
     * @return a X.509 Security Info.
     */
    public static SecurityInfo newX509CertInfo(String endpoint) {
        return new SecurityInfo(endpoint, null, null, null, true, false);
    }

    /**
     * Construct a {@link SecurityInfo} meaning that client with given endpoint name should authenticate itself using
     * X.509 mode with EST trusted X.509 Certificate.
     * <p>
     * By default, the certificate Common Name (CN) MUST match the endpoint name.
     *
     * @param endpoint the endpont name of the client.
     * @return a EST Security Info.
     */
    public static SecurityInfo newESTInfo(String endpoint) {
        return new SecurityInfo(endpoint, null, null, null, false, true);
    }

    /**
     * @return the client endpoint name.
     */
    public String getEndpoint() {
        return endpoint;
    }

    /**
     * @return the Pre-Shared-Key identity or <code>null</code> if {@link #usePSK()} return <code>false</code>.
     * @see #getPreSharedKey()
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * @return the Pre-Shared-Key or <code>null</code> if {@link #usePSK()} return <code>false</code>.
     * @see #getIdentity()
     */
    public byte[] getPreSharedKey() {
        return preSharedKey;
    }

    /**
     * @return <code>true</code> if this client should use PSK authentication.
     */
    public boolean usePSK() {
        return identity != null && preSharedKey != null;
    }

    /**
     * @return the {@link PublicKey} or <code>null</code> if {@link #useRPK()} returns <code>false</code>.
     */
    public PublicKey getRawPublicKey() {
        return rawPublicKey;
    }

    /**
     * @return <code>true</code> if this client should use RPK authentication.
     */
    public boolean useRPK() {
        return rawPublicKey != null;
    }

    /**
     * @return <code>true</code> if this client should use X.509 authentication.
     */
    public boolean useX509Cert() {
        return useX509Cert;
    }

    /**
     * @return <code>true</code> if this client should use X.509 mode with EST authentication.
     */
    public boolean useEST() {
        return useEST;
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(endpoint, identity, rawPublicKey, useX509Cert, useEST);
        result = 31 * result + Arrays.hashCode(preSharedKey);
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        SecurityInfo that = (SecurityInfo) o;
        return (useX509Cert == that.useX509Cert) && (useEST == that.useEST) && Objects.equals(endpoint, that.endpoint)
                && Objects.equals(identity, that.identity) && Arrays.equals(preSharedKey, that.preSharedKey) && Objects
                .equals(rawPublicKey, that.rawPublicKey);
    }

    @Override
    public String toString() {
        // Note : preSharedKey is explicitly excluded from display for security purposes
        return String.format("SecurityInfo [endpoint=%s, identity=%s, rawPublicKey=%s, useX509Cert=%s, useEST=%s]", endpoint,
                identity, rawPublicKey, useX509Cert, useEST);
    }

}
