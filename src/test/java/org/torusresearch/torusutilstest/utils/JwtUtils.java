package org.torusresearch.torusutilstest.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import net.andreinc.mockneat.MockNeat;

import java.util.Calendar;
import java.util.Date;

public class JwtUtils {
    public static String generateIdToken(String email, Algorithm alg) {

        Date today = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(today);
        calendar.add(Calendar.MINUTE, 2);
        Date modifiedDate = calendar.getTime();

        return JWT.create()
                .withClaim("admin", false)
                .withClaim("name", email)
                .withClaim("email", email)
                .withSubject("email|" + email.split("@")[0]) // sub
                .withClaim("email_verified", true)
                .withAudience("torus-key-test") // aud
                .withExpiresAt(modifiedDate) // eat
                .withIssuer("torus-key-test") // iss
                .withIssuedAt(today) // iat
                .sign(alg);
    }

    public static String getRandomEmail() {
        MockNeat mock = MockNeat.threadLocal();
        return mock.emails().val();
    }
}