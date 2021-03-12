package org.eclipse.leshan.server.californium.est;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.leshan.server.est.CoapEstHandler;

import java.net.InetSocketAddress;
import java.security.Principal;

public class SimpleReEnroll extends CoapResource {
    private final CoapEstHandler coapEstHandler;

    public SimpleReEnroll(CoapEstHandler coapEstHandler) {
        super( "sren");
        this.coapEstHandler = coapEstHandler;
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
        int contentFormat = exchange.getRequestOptions().getContentFormat();

        if (contentFormat == 286) {
            // POST data is CSR in DER encoding
            int accept = exchange.getRequestOptions().getAccept();

            if (accept == 281 || accept == -1) {
                try {
                    Request request = exchange.advanced().getRequest();
                    EndpointContext context = request.getSourceContext();
                    InetSocketAddress peerAddress = context.getPeerAddress();
                    Principal senderIdentity = context.getPeerIdentity();

                    byte[] reqPayload = exchange.getRequestPayload();

                    byte[] data = this.coapEstHandler
                            .simpleReEnroll(peerAddress, senderIdentity, accept, contentFormat, reqPayload);

                    exchange.respond(CoAP.ResponseCode.CHANGED, data, 281);
                    return;
                } catch (Exception e) {
                    exchange.respond(CoAP.ResponseCode.BAD_GATEWAY, "");
                    return;
                }
            }
        }

        exchange.respond(CoAP.ResponseCode.BAD_GATEWAY, "");
    }
}