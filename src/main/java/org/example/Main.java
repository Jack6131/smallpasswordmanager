package org.example;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Key Generation
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Encrypt Data
        String data = "Hello Bouncy Castle!";
        byte[] encryptedData = Encryption.encrypt(data, keyPair.getPublic());
        System.out.println(encryptedData.toString());
        // Decrypt Data
        String decryptedData = Decryption.decrypt(encryptedData, keyPair.getPrivate());
        System.out.println("Decrypted Data: " + decryptedData);
    }
}