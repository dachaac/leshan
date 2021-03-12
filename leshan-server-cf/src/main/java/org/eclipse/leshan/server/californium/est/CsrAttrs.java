package org.eclipse.leshan.server.californium.est;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.leshan.server.est.CoapEstHandler;

import java.net.InetSocketAddress;
import java.security.Principal;

public class CsrAttrs extends CoapResource {
    private final CoapEstHandler coapEstHandler;

    public CsrAttrs(CoapEstHandler coapEstHandler) {
        super( "att");
        this.coapEstHandler = coapEstHandler;
    }

    @Override
    public void handleGET(CoapExchange exchange) {
        try {
            Request request = exchange.advanced().getRequest();
            EndpointContext context = request.getSourceContext();
            InetSocketAddress peerAddress = context.getPeerAddress();
            Principal senderIdentity = context.getPeerIdentity();

            byte[] data = coapEstHandler.getCsrAttrs(peerAddress, senderIdentity);

            exchange.respond(CoAP.ResponseCode.CONTENT, data, 285);
        }
        catch (Exception e)
        {
            exchange.respond(CoAP.ResponseCode.BAD_GATEWAY, "");
        }
    }
}
