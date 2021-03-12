package org.eclipse.leshan.server.californium;

import org.eclipse.californium.core.CoapResource;

public class WellKnownResource extends CoapResource {
    public WellKnownResource() {
        super(".well-known");
    }
}