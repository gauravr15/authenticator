package com.odin.authenticator.utility;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Service
public class EncryptionDecryption {

    @Value("${encryption.key}")
    private String staticKey;

    // Encryption method
    public String encrypt(String data, String dynamicKey) throws Exception {
        SecretKeySpec secretKey = generateKey(staticKey + dynamicKey);  // Combine static and dynamic keys
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decryption method
    public String decrypt(String encryptedData, String dynamicKey) throws Exception {
        SecretKeySpec secretKey = generateKey(staticKey + dynamicKey);  // Combine static and dynamic keys
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // Generate a secret key by hashing the combined static and dynamic keys
    private SecretKeySpec generateKey(String combinedKey) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = combinedKey.getBytes(StandardCharsets.UTF_8);
        key = sha.digest(key);  // Hash the combined key with SHA-256 to ensure 256-bit length
        return new SecretKeySpec(key, "AES");
    }
}
