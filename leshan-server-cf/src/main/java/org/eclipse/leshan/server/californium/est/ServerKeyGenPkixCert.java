package org.eclipse.leshan.server.californium.est;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.leshan.server.est.CoapEstHandler;

public class ServerKeyGenPkixCert extends CoapResource {
    private final CoapEstHandler coapEstHandler;

    public ServerKeyGenPkixCert(CoapEstHandler coapEstHandler) {
        super( "skc");
        this.coapEstHandler = coapEstHandler;
    }
}
