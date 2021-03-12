package org.eclipse.leshan.server.californium.est;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.leshan.server.est.CoapEstHandler;

public class EstServiceResource extends CoapResource {
    public EstServiceResource(CoapEstHandler coapEstHandler) {
        super("est");

        add(new CaCerts(coapEstHandler));
        add(new CsrAttrs(coapEstHandler));
        add(new ServerKeyGenPkcs7(coapEstHandler));
        add(new ServerKeyGenPkixCert(coapEstHandler));
        add(new SimpleEnroll(coapEstHandler));
        add(new SimpleReEnroll(coapEstHandler));
    }
}
