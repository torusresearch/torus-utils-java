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
                .withSubject("email|" + email.split("@")[0])
                .withExpiresAt(modifiedDate)
                .withAudience("torus-key-test")
                .withClaim("isAdmin", false)
                .withClaim("emailVerified", true)
                .withIssuer("torus-key-test")
                .withIssuedAt(today)
                .withClaim("email", email)
                .withClaim("name", email)
                .sign(alg);
    }

    public static String getRandomEmail() {
        MockNeat mock = MockNeat.threadLocal();
        return mock.emails().val();
    }
}