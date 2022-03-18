package com.ibm.unlinkablepseudonyms;

import org.apache.commons.codec.digest.DigestUtils;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class Pseudonym {

    public static byte[] generate(byte[] payload, PRFSecretExponent secretExponent, RSAPublicKey publicKey) throws Exception {
        if (publicKey.getModulus().bitLength() <= 256) {
            throw new Exception("key size to small");
        }

        byte[] z = DigestUtils.sha3_256(payload);
        BigInteger b_z = new BigInteger(z);
        BigInteger nym = b_z.modPow(secretExponent.asBigInt(), publicKey.getModulus());
        return nym.toByteArray();
    }

    public static byte[] convert(
            byte[] cipher,
            PRFSecretExponent currentSecretExponent,
            PRFSecretExponent targetSecretExponent,
            RSAPrivateCrtKey privateKey) {

        BigInteger phi = privateKey.getPrimeP().subtract(BigInteger.ONE).multiply(privateKey.getPrimeQ().subtract(BigInteger.ONE));
        BigInteger value = (new BigInteger(cipher)).modPow(targetSecretExponent.asBigInt(), privateKey.getModulus());
        return value.modPow(currentSecretExponent.asBigInt().modInverse(phi), privateKey.getModulus()).toByteArray();
    }

}
