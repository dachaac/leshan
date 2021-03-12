package org.eclipse.leshan.server.est;

import java.net.InetSocketAddress;
import java.security.Principal;

public interface CoapEstHandler {
    byte[] getCaCerts(InetSocketAddress peerAddress, Principal senderIdentity) throws Exception;

    byte[] getCsrAttrs(InetSocketAddress peerAddress, Principal senderIdentity) throws Exception;

    byte[] simpleEnroll(InetSocketAddress peerAddress, Principal senderIdentity, int requestAccept,
            int requestContentFormat, byte[] requestPayload) throws Exception;

    byte[] simpleReEnroll(InetSocketAddress peerAddress, Principal senderIdentity, int requestAccept,
            int requestContentFormat, byte[] requestPayload) throws Exception;
}
