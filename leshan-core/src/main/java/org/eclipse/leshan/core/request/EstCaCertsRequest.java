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
package org.eclipse.leshan.core.request;

import org.eclipse.leshan.core.request.exception.InvalidRequestException;
import org.eclipse.leshan.core.response.BootstrapResponse;
import org.eclipse.leshan.core.response.EstCaCertsResponse;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * The request to send to start a bootstrap session
 */
public class EstCaCertsRequest extends AbstractLwM2mRequest<EstCaCertsResponse> implements UplinkRequest<EstCaCertsResponse> {

    public EstCaCertsRequest() {
        super(null);
    }

    @Override
    public void accept(UplinkRequestVisitor visitor) {
        visitor.visit(this);
    }

    @Override
    public String toString() {
        return "EstCaCertsRequest";
    }
}
