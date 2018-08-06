package net.prasenjit.identity;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jca.JCASupport;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

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
}
