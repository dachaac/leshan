/*******************************************************************************
 * Copyright (c) 2016 Sierra Wireless and others.
 * 
 * All rights reserved. This program and the accompanying materials are made available under the terms of the Eclipse
 * Public License v1.0 and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v20.html and the Eclipse Distribution
 * License is available at http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors: Sierra Wireless - initial API and implementation
 *******************************************************************************/
package org.eclipse.leshan.client.observer;

import java.security.cert.X509Certificate;
import java.util.concurrent.CopyOnWriteArrayList;

import org.eclipse.leshan.client.servers.ServerIdentity;
import org.eclipse.leshan.core.ResponseCode;
import org.eclipse.leshan.core.request.BootstrapRequest;
import org.eclipse.leshan.core.request.DeregisterRequest;
import org.eclipse.leshan.core.request.RegisterRequest;
import org.eclipse.leshan.core.request.UpdateRequest;

/**
 * A dispatcher for LwM2mClientObserver. It allow several observers on a LwM2mClient.
 *
 */
public class LwM2mClientObserverDispatcher implements LwM2mClientObserver {
    private CopyOnWriteArrayList<LwM2mClientObserver> observers = new CopyOnWriteArrayList<>();

    public void addObserver(LwM2mClientObserver observer) {
        observers.add(observer);
    }

    public void removeObserver(LwM2mClientObserver observer) {
        observers.remove(observer);
    }

    @Override
    public void onBootstrapStarted(ServerIdentity bsserver, BootstrapRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onBootstrapStarted(bsserver, request);
        }
    }

    @Override
    public void onBootstrapSuccess(ServerIdentity bsserver, BootstrapRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onBootstrapSuccess(bsserver, request);
        }
    }

    @Override
    public void onBootstrapFailure(ServerIdentity bsserver, BootstrapRequest request, ResponseCode responseCode,
            String errorMessage, Exception cause) {
        for (LwM2mClientObserver observer : observers) {
            observer.onBootstrapFailure(bsserver, request, responseCode, errorMessage, cause);
        }
    }

    @Override
    public void onBootstrapTimeout(ServerIdentity bsserver, BootstrapRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onBootstrapTimeout(bsserver, request);
        }
    }

    @Override
    public void onEstStarted(ServerIdentity bsserver) {
        for (LwM2mClientObserver observer : observers) {
            observer.onEstStarted(bsserver);
        }
    }

    @Override
    public void onEstReceivedCaCertificates(ServerIdentity estServer, X509Certificate[] caCertificates) {
        for (LwM2mClientObserver observer : observers) {
            observer.onEstReceivedCaCertificates(estServer, caCertificates);
        }
    }

    @Override
    public void onEstReceivedClientCertificates(ServerIdentity estServer, X509Certificate[] clientCertificates) {
        for (LwM2mClientObserver observer : observers) {
            observer.onEstReceivedClientCertificates(estServer, clientCertificates);
        }
    }

    @Override
    public void onEstSuccess(ServerIdentity bsserver) {
        for (LwM2mClientObserver observer : observers) {
            observer.onEstSuccess(bsserver);
        }
    }

    @Override
    public void onEstFailure(ServerIdentity bsserver, ResponseCode responseCode,
            String errorMessage, Exception cause) {
        for (LwM2mClientObserver observer : observers) {
            observer.onEstFailure(bsserver, responseCode, errorMessage, cause);
        }
    }

    @Override
    public void onEstTimeout(ServerIdentity bsserver) {
        for (LwM2mClientObserver observer : observers) {
            observer.onEstTimeout(bsserver);
        }
    }

    @Override
    public void onRegistrationStarted(ServerIdentity server, RegisterRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onRegistrationStarted(server, request);
        }
    }

    @Override
    public void onRegistrationSuccess(ServerIdentity server, RegisterRequest request, String registrationID) {
        for (LwM2mClientObserver observer : observers) {
            observer.onRegistrationSuccess(server, request, registrationID);
        }
    }

    @Override
    public void onRegistrationFailure(ServerIdentity server, RegisterRequest request, ResponseCode responseCode,
            String errorMessage, Exception cause) {
        for (LwM2mClientObserver observer : observers) {
            observer.onRegistrationFailure(server, request, responseCode, errorMessage, cause);
        }
    }

    @Override
    public void onRegistrationTimeout(ServerIdentity server, RegisterRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onRegistrationTimeout(server, request);
        }
    }

    @Override
    public void onUpdateStarted(ServerIdentity server, UpdateRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onUpdateStarted(server, request);
        }
    }

    @Override
    public void onUpdateSuccess(ServerIdentity server, UpdateRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onUpdateSuccess(server, request);
        }
    }

    @Override
    public void onUpdateFailure(ServerIdentity server, UpdateRequest request, ResponseCode responseCode, String errorMessage,
            Exception cause) {
        for (LwM2mClientObserver observer : observers) {
            observer.onUpdateFailure(server, request, responseCode, errorMessage, cause);
        }
    }

    @Override
    public void onUpdateTimeout(ServerIdentity server, UpdateRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onUpdateTimeout(server, request);
        }
    }

    @Override
    public void onDeregistrationStarted(ServerIdentity server, DeregisterRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onDeregistrationStarted(server, request);
        }
    }

    @Override
    public void onDeregistrationSuccess(ServerIdentity server, DeregisterRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onDeregistrationSuccess(server, request);
        }
    }

    @Override
    public void onDeregistrationFailure(ServerIdentity server, DeregisterRequest request, ResponseCode responseCode,
            String errorMessage, Exception e) {
        for (LwM2mClientObserver observer : observers) {
            observer.onDeregistrationFailure(server, request, responseCode, errorMessage, e);
        }
    }

    @Override
    public void onDeregistrationTimeout(ServerIdentity server, DeregisterRequest request) {
        for (LwM2mClientObserver observer : observers) {
            observer.onDeregistrationTimeout(server, request);
        }
    }

    @Override
    public void onUnexpectedError(Throwable unexpectedError) {
        for (LwM2mClientObserver observer : observers) {
            observer.onUnexpectedError(unexpectedError);
        }
    }
}
