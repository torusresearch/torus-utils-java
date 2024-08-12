package org.torusresearch.torusutilstest.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import net.andreinc.mockneat.MockNeat;

import java.math.BigInteger;
import java.util.Date;

public class JwtUtils {
    public static String generateIdToken(String email, Algorithm alg) {
        return JWT.create()
                .withSubject("email|" + email.split("@")[0])
                .withAudience("torus-key-test")
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600 * 1000))
                .withIssuedAt(new Date())
                .withIssuer("torus-key-test")
                .withClaim("email", email)
                .withClaim("nickname", email.split("@")[0])
                .withClaim("name", email)
                .withClaim("picture", "")
                .withClaim("email_verified", true)
                .sign(alg);
    }

    public static String getRandomEmail() {
        MockNeat mock = MockNeat.threadLocal();
        return mock.emails().val();
    }

    // TODO: This should be returned, not used as a comparison in the tests
    public static int getTimeDiff(BigInteger timestampInSeconds) {
        BigInteger timestampInMillis = timestampInSeconds.multiply(BigInteger.valueOf(1000));
        BigInteger systemTimestampMillis = BigInteger.valueOf(System.currentTimeMillis());
        BigInteger timeDifferenceMillis = systemTimestampMillis.subtract(timestampInMillis);
        BigInteger timeDifferenceSeconds = timeDifferenceMillis.divide(BigInteger.valueOf(1000));
        //System.out.println("Time difference: " + timeDifferenceSeconds + " seconds");
        return timeDifferenceSeconds.intValue();
    }
}
