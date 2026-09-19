package org.example;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

public class Encryption {
    public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] base) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm= new GCMParameterSpec(128,base);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key,"AES"),gcm);
        return cipher.doFinal(plaintext);
    }
}