package org.example;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

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
    public static void addWords(char[] entry, char[] masterPassword)
            throws IOException, GeneralSecurityException {

        VaultFile vault = readVaultFile();

        byte[] key = null;
        byte[] oldPlaintext = null;
        byte[] updatedPlaintext = null;
        byte[] ciphertext = null;
        byte[] newNonce = new byte[12];

        try {
            key = generateKey(masterPassword, vault.salt());

            // Validates password and retrieves existing vault data
            oldPlaintext = Decryption.decrypt(
                    vault.ciphertext(),
                    key,
                    vault.nonce()
            );

            String existing = new String(oldPlaintext, StandardCharsets.UTF_8);
            String newEntry = new String(entry);


            String updated;
            if (existing.equals("[]")) {
                updated = "[" + newEntry + "]";
            } else {
                updated = existing.substring(0, existing.length() - 1)
                        + "," + newEntry + "]";
            }

            updatedPlaintext = updated.getBytes(StandardCharsets.UTF_8);


            new SecureRandom().nextBytes(newNonce);

            ciphertext = encrypt(updatedPlaintext, key, newNonce);

            writeVaultFile(vault.salt(), newNonce, ciphertext);

        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            Arrays.fill(entry, '\0');
            Arrays.fill(masterPassword, '\0');

            if (key != null) Arrays.fill(key, (byte) 0);
            if (oldPlaintext != null) Arrays.fill(oldPlaintext, (byte) 0);
            if (updatedPlaintext != null) Arrays.fill(updatedPlaintext, (byte) 0);
            if (ciphertext != null) Arrays.fill(ciphertext, (byte) 0);

            Arrays.fill(newNonce, (byte) 0);
            Arrays.fill(vault.salt(), (byte) 0);
            Arrays.fill(vault.nonce(), (byte) 0);
            Arrays.fill(vault.ciphertext(), (byte) 0);
        }
    }
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


    private char[] masterPasswordSetUp(Console consol){

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
    private static byte[] generateKey(char[] password, byte[] salt){
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
    record VaultFile(byte[] salt, byte[] nonce, byte[] ciphertext) {}


    public static VaultFile readVaultFile() throws IOException {
        byte[] data = Files.readAllBytes(VAULT);

        int headerLength = 4 + 16 + 12;
        int tagLength = 16;

        if (data.length < headerLength + tagLength) {
            throw new IOException("Vault file is too short.");
        }

        if (data[0] != 'V' || data[1] != 'L'
                || data[2] != 'T' || data[3] != '1') {
            throw new IOException("Not a valid vault file.");
        }

        byte[] salt = Arrays.copyOfRange(data, 4, 20);
        byte[] nonce = Arrays.copyOfRange(data, 20, 32);
        byte[] ciphertext = Arrays.copyOfRange(data, 32, data.length);

        Arrays.fill(data, (byte) 0);

        return new VaultFile(salt, nonce, ciphertext);
    }

    public void signIn(Console consol) throws Exception {
        VaultFile vault= readVaultFile();
        char[] Password=consol.readPassword("Enter in your password:");
        byte[]key=generateKey(Password,vault.salt);
        byte[] plaintext = Decryption.decrypt(vault.ciphertext(), key, vault.nonce());
        System.out.println(new String(plaintext, StandardCharsets.UTF_8));

    }
   public void generateAccount(Console consol){
        char [] password = masterPasswordSetUp(consol);
        encryptPassword(password);


    }
}
