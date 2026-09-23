package org.example;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;

public class Decryption {
    public static byte[] decrypt(byte[] plaintext, byte[] key, byte[] base) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm= new GCMParameterSpec(128,base);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key,"AES"),gcm);
        return cipher.doFinal(plaintext);
    }
}