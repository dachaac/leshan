/*******************************************************************************
 * Copyright (c) 2015 Sierra Wireless and others.
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
package org.eclipse.leshan.core.response;

import org.eclipse.leshan.core.ResponseCode;

/**
 * The response to a client bootstrap request.
 */
public class EstCaCertsResponse extends AbstractLwM2mResponse {

    final private byte [] payload;

    public EstCaCertsResponse(ResponseCode code, String errorMessage, byte[] payload) {
        this(code, errorMessage, null, payload);
    }

    public EstCaCertsResponse(ResponseCode code, String errorMessage, Object coapResponse, byte[] payload) {
        super(code, errorMessage, coapResponse);
        this.payload = payload;
    }

    public byte[] getPayload() {
        return this.payload;
    }

    @Override
    public boolean isSuccess() {
        return getCode() == ResponseCode.CONTENT;
    }

    @Override
    public boolean isValid() {
        switch (code.getCode()) {
        case ResponseCode.CONTENT_CODE:
        case ResponseCode.BAD_REQUEST_CODE:
        case ResponseCode.INTERNAL_SERVER_ERROR_CODE:
            return true;
        default:
            return false;
        }
    }

    @Override
    public String toString() {
        if (errorMessage != null)
            return String.format("EstCaCertsResponse [code=%s, errormessage=%s]", code, errorMessage);
        else
            return String.format("EstCaCertsResponse [code=%s]", code);
    }

    // Syntactic sugar static constructors :

    public static EstCaCertsResponse success(byte[] payload) {
        return new EstCaCertsResponse(ResponseCode.CONTENT, null, payload);
    }

    public static EstCaCertsResponse badRequest(String errorMessage) {
        return new EstCaCertsResponse(ResponseCode.BAD_REQUEST, errorMessage, null);
    }

    public static EstCaCertsResponse internalServerError(String errorMessage) {
        return new EstCaCertsResponse(ResponseCode.INTERNAL_SERVER_ERROR, errorMessage, null);
    }
}
