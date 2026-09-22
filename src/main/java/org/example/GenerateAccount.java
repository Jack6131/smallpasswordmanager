package org.example;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.example.Encryption.encrypt;


public class GenerateAccount {
    private static final Path VAULT = Path.of("vault.dat");
    private static final byte[] MAGIC = { 'V', 'L', 'T', '1' };
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
        Console consol= System.console();
        char[] PasswordInitialization=consol.readPassword("Create Master Password \nRules For Password:\n \t1.Password Must Contain a Number and Letter\n \t2.Must be MORE than 12 Characters\n \t3.NO Whitespace \nEnter Password:");
        char[] ValidatePassword = consol.readPassword("Confirm Password:");
        while (!Arrays.equals(PasswordInitialization,ValidatePassword)|| !checkPassword(PasswordInitialization)){
            consol.printf("Passwords don't match or did not follow the rules!\nTry Again!\n");
            Arrays.fill(PasswordInitialization, '\0');
            Arrays.fill(ValidatePassword, '\0');
            PasswordInitialization=consol.readPassword("Create Master Password:");
            ValidatePassword = consol.readPassword("Confirm Password:");
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
            writeVaultFile(salt,base,encrypted);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }finally {
            Arrays.fill(password, '\0');
        }
    }
    private static void writeVaultFile(byte[] salt, byte[] nonce, byte[] ciphertext)
            throws IOException {

        Path temp = Path.of("vault.dat.tmp");

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(MAGIC);
        output.write(salt);
        output.write(nonce);
        output.write(ciphertext);

        Files.write(temp, output.toByteArray());

        Files.move(
                temp,
                VAULT,
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE
        );
    }

   public void generateAccount(){
        char [] password = masterPasswordSetUp();
        encryptPassword(password);


    }
}
