package net.prasenjit.identity;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jca.JCASupport;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

import static org.junit.Assert.assertEquals;

public class JwtTest {

    @Test
    public void testJwt() throws NoSuchAlgorithmException, JOSEException, ParseException {

        BouncyCastleProvider bc = BouncyCastleProviderSingleton.getInstance();
        Security.addProvider(bc);

        System.out.println(JCASupport.isSupported(EncryptionMethod.A256CBC_HS512));

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().issuer("ccs")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .claim("key", "value")
                .audience("ccs")
                .build();

        RSASSASigner rsassaSigner = new RSASSASigner(keyPair.getPrivate());

        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        signedJWT.sign(rsassaSigner);

        String token = signedJWT.serialize();
        System.out.println(token);
        System.out.println(token.length());

        JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build();
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(token));
        JWEEncrypter rsaEncryptor = new RSAEncrypter((RSAPublicKey) keyPair.getPublic());
        jweObject.encrypt(rsaEncryptor);

        System.out.println(jweObject.serialize());
        System.out.println(jweObject.serialize().length());

        jweObject = JWEObject.parse(jweObject.serialize());
        JWEDecrypter rsaDecryptor = new RSADecrypter(keyPair.getPrivate());
        jweObject.decrypt(rsaDecryptor);

        signedJWT = jweObject.getPayload().toSignedJWT();

        RSASSAVerifier rsassaVerifier = new RSASSAVerifier((RSAPublicKey) keyPair.getPublic());
        signedJWT.verify(rsassaVerifier);

        assertEquals("ccs", signedJWT.getJWTClaimsSet().getIssuer());
    }

    @Test
    public void JWTValidationTest() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey secretKey = generator.generateKey();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().issuer("ccs")
                .expirationTime(new Date(System.currentTimeMillis()))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).build();
        SignedJWT jwt = new SignedJWT(header, claimsSet);

        MACSigner signer = new MACSigner(secretKey);

        jwt.sign(signer);


        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWKSource<SecurityContext> source = new ImmutableSecret<>(secretKey);
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, source);
        jwtProcessor.setJWSKeySelector(keySelector);

        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<SecurityContext>() {
            @Override
            public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
                super.verify(claimsSet, context);

                if (!"ccs".equals(claimsSet.getIssuer())) {
                    throw new BadJWTException("Invalid issuer");
                }
            }
        });

        JWTClaimsSet receivedClaim = jwtProcessor.process(jwt.serialize(), null);
        System.out.println(receivedClaim.toJSONObject());
    }
}
