import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Represents an RSA key, keeping track of the plaintext, ciphertext, public key, and private key.
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 * 4/29/2015
 */
public class RsaKey {
    /** the private key */
    private BigInteger privateKey;
    private BigInteger publicExponent;
    /** the modulus portion of the public key */
    private BigInteger publicModulus;
    /** the ciphertext */
    private BigInteger ciphertext;
    /** the plaintext */
    private BigInteger plaintext;
    /** a string representation of the plaintext */
    private String plaintextString;

    /**
     * Constructs an RsaKey object
     *
     * @param publicExponent the exponent
     * @param publicModulus the mod
     * @param ciphertext a ciphertext encrypted with this key
     */
    public RsaKey(BigInteger publicModulus, BigInteger publicExponent, BigInteger ciphertext) {
        this.publicExponent = publicExponent;
        this.publicModulus = publicModulus;
        this.ciphertext = ciphertext;
    }

    /**
     * Gets the private key
     *
     * @return the private key
     */
    public BigInteger getPrivateKey() {
        return privateKey;
    }

    /**
     * Gets the public modulus
     *
     * @return the public modulus
     */
    public BigInteger getPublicModulus() {
        return publicModulus;
    }

    /**
     * Gets the ciphertext
     *
     * @return the ciphertext
     */
    public BigInteger getCiphertext() {
        return ciphertext;
    }

    /**
     * Gets the string representation of the plaintext
     *
     * @return the plaintext
     */
    public String getPlaintextString() {
        return plaintextString;
    }

    /**
     * Sets the plaintext and decodes it into a string
     *
     * @param plaintext the plaintext (a string)
     */
    public void setPlaintext(BigInteger plaintext) {
        this.plaintext = plaintext;
        decodePlaintextBigInt();
    }

    /**
     * Determines the private key given one of the factors of the public modulus
     *
     * @param p the factor of the modulus
     */
    public void determinePrivateKey(BigInteger p) {
        BigInteger q = publicModulus.divide(p);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        this.privateKey = publicExponent.modInverse(phi);
    }

    /**
     * Decodes the plaintext into a UTF-8 string
     */
    private void decodePlaintextBigInt() {
        byte[] plaintextBytesAll = plaintext.toByteArray();
        int plaintextLength = plaintextBytesAll[1] & 255;
        byte[] plaintextBytesString = Arrays.copyOfRange(plaintextBytesAll, 2, plaintextLength + 2);
        try {
            plaintextString = new String(plaintextBytesString, "UTF-8");
        } catch(UnsupportedEncodingException e) {
            System.err.println("Invalid encoding");
            System.exit(1);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof RsaKey) {
            RsaKey k = (RsaKey) obj;
            return k.getCiphertext().equals(this.ciphertext) && k.getPublicModulus().equals(this.publicModulus)
                    && k.getPublicExponent().equals(this.publicExponent);
        } else {
            return false;
        }
    }

    /** the exponent portion of the public key */
    public BigInteger getPublicExponent() {
        return publicExponent;
    }
}
