package org.example;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.example.Encryption.encrypt;

public class GenerateAccount {
    private boolean checkPassword(char [] password){
        boolean hasNumber=false;
        boolean hasLetter=false;
        if(password.length<10){
            return false;
        }
        for (char c:password){
            if(Character.isWhitespace(c)){
                return false;
            }
            if(Character.isLetter(c)){
                hasLetter=true;
            }
            if(Character.isDigit(c)){
                hasNumber=true;
            }


        }
        return hasLetter&&hasNumber;
    }


    private char[] masterPasswordSetUp(){
        Console console= System.console();
        char[] PasswordInitialization=console.readPassword("Create Master Password \n Rules For Password:\n \t 1.Password Must Contain a Number and Letter\n \t 2.Must be MORE than 12 Characters\n \t 3.NO Whitespace \n Enter Password:");
        char[] ValidatePassword = console.readPassword("Confirm Password:");
        while (!Arrays.equals(PasswordInitialization,ValidatePassword)&& checkPassword(PasswordInitialization)){
            console.printf("Passwords don't match or did not follow the rules!\n Try Again!");
            Arrays.fill(PasswordInitialization, '\0');
            Arrays.fill(ValidatePassword, '\0');
            PasswordInitialization=console.readPassword("Create Master Password");
            ValidatePassword = console.readPassword("Confirm Password:");
        }
        return PasswordInitialization;
    }
    private byte[] generateKey(char[]password, byte[]salt){
        byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);
        try{
        Argon2Parameters param= new Argon2Parameters.Builder(
                Argon2Parameters.ARGON2_id).withSalt(salt)
                .withMemoryAsKB(64*1024)
                .withIterations(3)
                .withParallelism(1)
                .build();
        Argon2BytesGenerator argon2= new Argon2BytesGenerator();
        argon2.init(param);
        byte[]key= new byte[32];
        argon2.generateBytes(passwordBytes,key);
        return key;
        }
        finally {
            Arrays.fill(passwordBytes,(byte) 0);
        }
    }
    private void encryptPassword(char [] password){
        try{
        byte[]salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        byte []key = generateKey(password,salt);
        try{
            byte [] base = new byte[12];
            new SecureRandom().nextBytes(base);
            byte[] encrypted= encrypt("[]".getBytes(StandardCharsets.UTF_8),key,base);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }finally {
            Arrays.fill(password, '\0');
        }
    }

   public void generateAccount(){
        char [] password = masterPasswordSetUp();
        encryptPassword(password);


    }
}
