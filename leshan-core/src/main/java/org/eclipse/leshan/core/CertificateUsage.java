package org.eclipse.leshan.core;

public enum CertificateUsage {
    CA_CONSTRAINT(0), SERVICE_CERTIFICATE_CONSTRAINT(1), TRUST_ANCHOR_ASSERTION(2), DOMAIN_ISSUER_CERTIFICATE(3);

    public final int code;

    private CertificateUsage(int code) {
        this.code = code;
    }

    public static CertificateUsage fromCode(long code) {
        return fromCode((int) code);
    }

    public static CertificateUsage fromCode(int code) {
        for (CertificateUsage sm : CertificateUsage.values()) {
            if (sm.code == code) {
                return sm;
            }
        }
        throw new IllegalArgumentException(String.format("Unsupported certificate usage code : %d", code));
    }
}
