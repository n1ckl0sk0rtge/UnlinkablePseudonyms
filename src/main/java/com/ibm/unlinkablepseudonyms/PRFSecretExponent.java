package com.ibm.unlinkablepseudonyms;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

public class PRFSecretExponent {

    byte[] data;

    public PRFSecretExponent(int bits, RSAPrivateCrtKey privateKey) {
        BigInteger phi = privateKey.getPrimeP().subtract(BigInteger.ONE).multiply(privateKey.getPrimeQ().subtract(BigInteger.ONE));
        BigInteger x = new BigInteger(bits, new SecureRandom());
        while ( !(x.gcd(phi).equals(BigInteger.ONE)) && (x.compareTo(BigInteger.ONE) > 0) ) {
            x = new BigInteger(bits, new SecureRandom());
        }
        this.data = x.toByteArray();
    }

    public PRFSecretExponent(String base64) {
        this.data = Base64.getDecoder().decode(base64);
    }

    public BigInteger asBigInt() {
        return new BigInteger(this.data);
    }

    public String asBase64() {
        return Base64.getEncoder().encodeToString(this.data);
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }
}
