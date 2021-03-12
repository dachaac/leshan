package org.eclipse.leshan.server.californium.est;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.leshan.server.est.CoapEstHandler;

public class ServerKeyGenPkcs7 extends CoapResource {
    private final CoapEstHandler coapEstHandler;

    public ServerKeyGenPkcs7(CoapEstHandler coapEstHandler) {
        super( "skg");
        this.coapEstHandler = coapEstHandler;
    }
}
