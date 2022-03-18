import com.ibm.unlinkablepseudonyms.PRFSecretExponent;
import com.ibm.unlinkablepseudonyms.Pseudonym;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class PseudonymTest {

    @Test
    public void positiveTest() {

        try {
            Base64.Encoder b64Enc = Base64.getEncoder();

            String input = "testIdentifier";

            // Converter
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(1024);
            KeyPair prfPair = keyPairGen.generateKeyPair();

            PRFSecretExponent xa = new PRFSecretExponent(256, (RSAPrivateCrtKey) prfPair.getPrivate());
            byte[] pseuA = Pseudonym.generate(input.getBytes(), xa, (RSAPublicKey) prfPair.getPublic());
            PRFSecretExponent xb = new PRFSecretExponent(256, (RSAPrivateCrtKey) prfPair.getPrivate());
            byte[] pseuB = Pseudonym.generate(input.getBytes(), xb, (RSAPublicKey) prfPair.getPublic());

            // Server A
            System.out.println(b64Enc.encodeToString(pseuA));

            // Server B
            System.out.println(b64Enc.encodeToString(pseuB));

            // Converter
            byte[] pseuAinB = Pseudonym.convert(pseuA, xa, xb, (RSAPrivateCrtKey) prfPair.getPrivate());

            // Server B
            System.out.println(b64Enc.encodeToString(pseuAinB));
            assertEquals(b64Enc.encodeToString(pseuB), b64Enc.encodeToString(pseuAinB));

        } catch (Exception e) {
            fail(e);
        }

    }

    @Test
    public void negativeTest() {

        try {
            Base64.Encoder b64Enc = Base64.getEncoder();

            String input = "testIdentifier";

            // Converter
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(256);
            KeyPair prfPair = keyPairGen.generateKeyPair();

            PRFSecretExponent xa = new PRFSecretExponent(256, (RSAPrivateCrtKey) prfPair.getPrivate());
            byte[] pseuA = Pseudonym.generate(input.getBytes(), xa, (RSAPublicKey) prfPair.getPublic());

            fail();

        } catch (Exception e) { }

    }


}
