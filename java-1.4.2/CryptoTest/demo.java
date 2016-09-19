
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * demo class to implement AES encryption and decryption for given string
 */
public class demo {
    public static void main(String[] args) throws UnsupportedEncodingException, GeneralSecurityException {
//         String ciphertext = "U2FsdGVkX1+0m/gle/XQX1shjnpveUrl1fO3oOlurPMlTks6+oQlEPfOrucihzEz";
        String ciphertext = "U2FsdGVkX19cGat1ukjUnqn009HoRKWua0DDi52W7K0FwEuDCIOEJPV5xTTKUPml";
        String plaintext = "This is some example plaintext";
        String password = "This is a very strong password";

        int keySize = 256;
        int ivSize = 128;
        Cipher cipher;
        
        System.out.println("Printing Results...");

        try {
            byte[] ctBytes = new sun.misc.BASE64Decoder().decodeBuffer(ciphertext);
            byte[] initial_bytes = getInitialByte(); // This variable is used when returning encrypted string
            byte[] saltBytes = new byte[8], ciphertextBytes = new byte[ctBytes.length - 16];
            System.arraycopy(ctBytes, 8, saltBytes, 0, 8);
            System.arraycopy(ctBytes, 16, ciphertextBytes, 0, ctBytes.length - 16);

            byte[] key = new byte[keySize/8];
            byte[] iv = new byte[ivSize/8];
            EvpKDF(password.getBytes("UTF-8"), keySize, ivSize, saltBytes, key, iv);

            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] recoveredPlaintextBytes = cipher.doFinal(ciphertextBytes);
            String recoveredPlaintext = new String(recoveredPlaintextBytes);

            System.out.println("Recovered Plaintext: " + recoveredPlaintext);

            /**
             * Encrypt Test
             */
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

            byte[] encrypted_bytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
            
            byte[] enc_bytes_with_salt = new byte[initial_bytes.length + encrypted_bytes.length];
            System.arraycopy(initial_bytes, 0, enc_bytes_with_salt, 0, initial_bytes.length);
            System.arraycopy(encrypted_bytes, 0, enc_bytes_with_salt, initial_bytes.length, encrypted_bytes.length);
            String encrypted_str_b64 = "";
            try {
                encrypted_str_b64 = new sun.misc.BASE64Encoder().encode(enc_bytes_with_salt);
                System.out.println("Plaintext: " + plaintext);
                System.out.println("Encrypted text: " + encrypted_str_b64);
            } catch (Exception e) {
            	System.out.println("Catching error in encrypt:" + e.toString());
            	e.printStackTrace();
            }
            
            /**
             * Decrypt Test
             */
            try {
                byte[] cipher_text_bytes_with_salt = new sun.misc.BASE64Decoder().decodeBuffer(ciphertext);
                byte[] cipher_text_bytes = new byte[cipher_text_bytes_with_salt.length - 16];
                System.arraycopy(cipher_text_bytes_with_salt, 16, cipher_text_bytes, 0, cipher_text_bytes_with_salt.length - 16);
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                String decrypted = new String(cipher.doFinal(cipher_text_bytes));
                
                System.out.println("Decrypted text: " + decrypted);
            } catch (Exception e) {
            	System.out.println("Catching error in decrypt:" + e.toString());
            	e.printStackTrace();
            }
        } catch (Exception e) {
            System.out.println("Catching error:" + e.toString());
            e.printStackTrace();
        }
        
    }

    public static byte[] EvpKDF(byte[] password, int keySize, int ivSize, byte[] salt, byte[] resultKey, byte[] resultIv) throws NoSuchAlgorithmException {
        return EvpKDF(password, keySize, ivSize, salt, 1, "MD5", resultKey, resultIv);
    }

    public static byte[] EvpKDF(byte[] password, int keySize, int ivSize, byte[] salt, int iterations, String hashAlgorithm, byte[] resultKey, byte[] resultIv) throws NoSuchAlgorithmException {
        keySize = keySize / 32;
        ivSize = ivSize / 32;
        int targetKeySize = keySize + ivSize;
        byte[] derivedBytes = new byte[targetKeySize * 4];
        int numberOfDerivedWords = 0;
        byte[] block = null;
        MessageDigest hasher = MessageDigest.getInstance(hashAlgorithm);
        while (numberOfDerivedWords < targetKeySize) {
            if (block != null) {
                hasher.update(block);
            }
            hasher.update(password);
            block = hasher.digest(salt);
            hasher.reset();

            // Iterations
            for (int i = 1; i < iterations; i++) {
                block = hasher.digest(block);
                hasher.reset();
            }

            System.arraycopy(block, 0, derivedBytes, numberOfDerivedWords * 4,
                    Math.min(block.length, (targetKeySize - numberOfDerivedWords) * 4));

            numberOfDerivedWords += block.length/4;
        }

        System.arraycopy(derivedBytes, 0, resultKey, 0, keySize * 4);
        System.arraycopy(derivedBytes, keySize * 4, resultIv, 0, ivSize * 4);

        return derivedBytes; // key + iv
    }

    /**
     * Convert Hex String to Byte Array
     * @param  s [Hex String]
     * @return   byte[] data
     */
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    /**
     * [getInitialByte return initial bytes to be added in first of encrypted bytes]
     * @return byte[] initial_bytes
     * @throws UnsupportedEncodingException
     */
    public static byte[] getInitialByte() throws UnsupportedEncodingException {
        String sample_ciphertext = "U2FsdGVkX1+0m/gle/XQX1shjnpveUrl1fO3oOlurPMlTks6+oQlEPfOrucihzEz";
        byte[] initial_bytes = new byte[16];
        try {
            byte[] ct_bytes = new sun.misc.BASE64Decoder().decodeBuffer(sample_ciphertext);    
            System.arraycopy(ct_bytes, 0, initial_bytes, 0 , 16);
        } catch (Exception e) {
        	System.out.println("Catching error in getInitialByte:" + e.toString());
            e.printStackTrace();
        }
        return initial_bytes;
    }
}