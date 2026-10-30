package io.quarkiverse.mcp.servers.jdbc.secret;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HKDF-SHA256 (RFC 5869) with an empty salt, used to derive one independent key per purpose from the master key. */
public final class Hkdf {

    private static final String HMAC = "HmacSHA256";

    private Hkdf() {
    }

    public static byte[] derive(byte[] masterKey, String purpose, int length) {
        if (length < 1 || length > 255 * 32) {
            throw new IllegalArgumentException("Invalid length");
        }
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(new byte[32], HMAC));
            byte[] prk = mac.doFinal(masterKey);

            mac.init(new SecretKeySpec(prk, HMAC));
            byte[] info = purpose.getBytes(StandardCharsets.UTF_8);
            byte[] okm = new byte[length];
            byte[] t = new byte[0];
            int pos = 0;
            for (byte counter = 1; pos < length; counter++) {
                mac.update(t);
                mac.update(info);
                mac.update(counter);
                t = mac.doFinal();
                int n = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, okm, pos, n);
                pos += n;
            }
            return okm;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF unavailable", e);
        }
    }
}
