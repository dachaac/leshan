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

import org.eclipse.leshan.core.response.EstCaCertsResponse;
import org.eclipse.leshan.core.response.EstSimpleEnrollResponse;

/**
 * The request to send to start a bootstrap session
 */
public class EstSimpleEnrollRequest extends AbstractLwM2mRequest<EstSimpleEnrollResponse>  implements UplinkRequest<EstSimpleEnrollResponse> {

    final private byte [] csrDerData;

    public EstSimpleEnrollRequest(byte [] csrDerData) {
        super(null);
        this.csrDerData = csrDerData;
    }

    @Override
    public void accept(UplinkRequestVisitor visitor) {
        visitor.visit(this);
    }

    @Override
    public String toString() {
        return "EstSimpleEnrollRequest";
    }

    public byte[] getPayload() {
        return this.csrDerData;
    }
}
