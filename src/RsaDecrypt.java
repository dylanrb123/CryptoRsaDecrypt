import java.io.FileNotFoundException;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Decrypts 2..n RSA ciphertexts given the public key and ciphertext for each. Each public key is assumed to share a
 * common large prime factor p, which is used to exploit the algorithm and determine the private key, used to decrypt
 * the ciphertext.
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 * 4/22/2015
 */
public class RsaDecrypt {
    /**
     * The main method. Reads the input file and checks for errors.
     *
     * @param args the command line arguments (not used)
     */
    public static void main(String[] args) {
        // handle all error conditions
        if (args.length != 1) {
            System.err.println("Usage: java RsaDecrypt <file>");
            System.err.println("<file> is the name of the file containing groups of (RSA modulus, RSA exponent, ciphertext)");
            System.exit(1);
        }
        Scanner fileScanner = null;
        String fileName = args[0];
        try {
            fileScanner = new Scanner(new FileReader(fileName));
        } catch (FileNotFoundException e) {
            System.err.println("Unable to open file " + fileName);
            System.exit(1);
        }
        List<String> inputLines = new ArrayList<>();
        while (fileScanner.hasNext()) {
            inputLines.add(fileScanner.nextLine());
        }
        if (inputLines.size() % 3 != 0) {
            System.err.println("Invalid file contents");
            System.exit(1);
        }
        // parse the file
        List<RsaKey> rsaKeys = new ArrayList<>();
        for (int i = 0; i < inputLines.size(); i += 3) {
            try {
                RsaKey key = new RsaKey(new BigInteger(inputLines.get(i)), new BigInteger(inputLines.get(i + 1)),new BigInteger(inputLines.get(i + 2)));
                rsaKeys.add(key);
            } catch (NumberFormatException e) {
                System.err.println("File contains non-numeric characters");
                System.exit(1);
            }
        }
        if(rsaKeys.size() < 2) {
            System.err.println("Need at least two groups of public key-ciphertext information");
            System.exit(1);
        }

        // determine the plaintexts
        List<String> plaintextStrings = getPlaintexts(rsaKeys);
        // display the strings
        for(String s : plaintextStrings) {
            System.out.println(s);
        }

    }

    /**
     * Determines all of the plaintexts based on the given RSA keys. Assumes that all of the public keys share a
     * common non-trivial factor.
     *
     * @param keys the RSA key objects
     * @return a list of the decrypted plaintexts
     */
    private static List<String> getPlaintexts(List<RsaKey> keys) {
        List<String> plaintexts = new ArrayList<>();

        for(RsaKey key : keys) {
            BigInteger sharedFactor = BigInteger.ONE;
            for (RsaKey key1 : keys) {
                sharedFactor = key.getPublicModulus().gcd(key1.getPublicModulus());
                if (!sharedFactor.equals(BigInteger.ONE) && !key.equals(key1)) break;
            }
            key.determinePrivateKey(sharedFactor);
            key.setPlaintext(key.getCiphertext().modPow(key.getPrivateKey(), key.getPublicModulus()));
            plaintexts.add(key.getPlaintextString());
        }
        return plaintexts;
    }
}
