package com.ibm.unlinkablepseudonyms;

import org.apache.commons.codec.digest.DigestUtils;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class Pseudonym {

    public static byte[] generate(byte[] identifier, PRFSecretExponent secretExponent, RSAPublicKey converterKey) {
        byte[] b_uid = DigestUtils.sha256(identifier);
        BigInteger uid = new BigInteger(b_uid);
        BigInteger nym = uid.modPow(secretExponent.asBigInt(), converterKey.getModulus());
        return nym.toByteArray();
    }

    public static byte[] convert(
            byte[] cipher,
            PRFSecretExponent currentSecretExponent,
            PRFSecretExponent targetSecretExponent,
            RSAPrivateCrtKey privateKey) {

        BigInteger value = (new BigInteger(cipher)).modPow(targetSecretExponent.asBigInt(), privateKey.getModulus());
        BigInteger phi = privateKey.getPrimeP().subtract(BigInteger.ONE).multiply(privateKey.getPrimeQ().subtract(BigInteger.ONE));
        return value.modPow(currentSecretExponent.asBigInt().modInverse(phi), privateKey.getModulus()).toByteArray();
    }

}
