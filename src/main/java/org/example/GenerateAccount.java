package org.example;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
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
import java.util.HashMap;
import java.util.HexFormat;
import java.util.concurrent.Executors;

import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static java.lang.Thread.sleep;
import static org.example.Encryption.encrypt;

public class GenerateAccount {

    public record IndexEntry(String id, String service) {}


    private static final byte[] MAGIC = { 'V', 'L', 'T', '1' };


    private static final SecureRandom RANDOM = new SecureRandom();


    private static void passwordToClipboard(char[] password) throws InterruptedException {
        Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();
        StringSelection stringSelection = new StringSelection("");
        clip.setContents(new StringSelection(new String(password)),null);
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                clip.setContents(stringSelection,null);
            }
        }));
        try{

        Thread.sleep(30000);

        clip.setContents(stringSelection, null);
        }
        catch(InterruptedException e){
            Thread.currentThread().interrupt();
            clip.setContents(stringSelection, null);

        }
    }
    //makes a random id to link the index file with a vault file in the entries directory so it knows where to look for your password
    private static String generateEntryId() {
        byte[] bytes = new byte[16]; // 128-bit ID
        RANDOM.nextBytes(bytes);

        try {
            return HexFormat.of().formatHex(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }
    public static void addWords(
            char[] indexEntryJson,
            char[] entryPassword,
            char[] masterPassword
    ) throws IOException, GeneralSecurityException {

        VaultFile vault = readVaultFile(VaultPaths.INDEX_FILE);

        byte[] key = null;
        byte[] oldPlaintext = null;
        byte[] updatedIndexPlaintext = null;
        byte[] entryPlaintext = null;
        byte[] indexCiphertext = null;
        byte[] entryCiphertext = null;

        byte[] indexNonce = new byte[12];
        byte[] entryNonce = new byte[12];

        String id = generateEntryId();

        try {
            key = generateKey(masterPassword, vault.salt());

            oldPlaintext = Decryption.decrypt(vault.ciphertext(), key, vault.nonce());

            String existing = new String(oldPlaintext, StandardCharsets.UTF_8);
            //This might be used for later if I ever want to do json formatting
           // String newIndexJson = ("{\"id\":\""+id+"\",\"service\":\""+new String(indexEntryJson)+"\"}");

            String updatedIndexJson = existing+id+"\n"+new String(indexEntryJson)+"\n";

            updatedIndexPlaintext =
                    updatedIndexJson.getBytes(StandardCharsets.UTF_8);

            entryPlaintext = StandardCharsets.UTF_8.encode(
                    java.nio.CharBuffer.wrap(entryPassword)
            ).array();

            SecureRandom random = new SecureRandom();
            random.nextBytes(indexNonce);
            random.nextBytes(entryNonce);

            entryCiphertext = encrypt(entryPlaintext, key, entryNonce);

            writeVaultFile(
                    VaultPaths.entryFile(id),
                    vault.salt(),
                    entryNonce,
                    entryCiphertext
            );

            indexCiphertext = encrypt(updatedIndexPlaintext, key, indexNonce);

            writeVaultFile(
                    VaultPaths.INDEX_FILE,
                    vault.salt(),
                    indexNonce,
                    indexCiphertext
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            Arrays.fill(indexEntryJson, '\0');
            Arrays.fill(entryPassword, '\0');
            Arrays.fill(masterPassword, '\0');

            wipe(key);
            wipe(oldPlaintext);
            wipe(updatedIndexPlaintext);
            wipe(entryPlaintext);
            wipe(indexCiphertext);
            wipe(entryCiphertext);
            wipe(indexNonce);
            wipe(entryNonce);

            wipe(vault.salt());
            wipe(vault.nonce());
            wipe(vault.ciphertext());
        }
    }

    //clears data after its passed its usage so it cant be accessed illegally later
    private static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    //just some simple password rules
    private static boolean checkPassword(char[] password){
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


    //asks you to generate a password that will be used as the basis of your vault file
    private static char[] masterPasswordSetUp(Console consol){

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


    //takes a given password and genenrates a key that will be used for encryption
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

    //using master password generates a key that then will be used to write a vault file that will store the encrypted plain text
    private static void encryptPassword(Path target, char[] password){
        try{
        byte[]salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        byte []key = generateKey(password,salt);
        try{
            byte [] base = new byte[12];
            new SecureRandom().nextBytes(base);
            byte[] encrypted= encrypt("".getBytes(StandardCharsets.UTF_8),key,base);
            writeVaultFile(target,salt,base,encrypted);
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

    //the physical writing of the vault file
    private static void writeVaultFile(
            Path target, byte[] salt, byte[] nonce, byte[] ciphertext
    ) throws IOException {
        Path temp = Files.createTempFile(
                target.getParent(),
                target.getFileName().toString(),
                ".tmp"
        );

        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            output.write(MAGIC);
            output.write(salt);
            output.write(nonce);
            output.write(ciphertext);

            Files.write(temp, output.toByteArray());

            Files.move(
                    temp,
                    target,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
            );
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    record VaultFile(byte[] salt, byte[] nonce, byte[] ciphertext) {}


    //returns the encrypted plain text of the vault file
    public static VaultFile readVaultFile(Path p) throws IOException {
        byte[] data = Files.readAllBytes(p);

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

    public static void getPassword(Console consol)throws Exception{
        HashMap<String, String> map = new HashMap<>();
        char[] Password=consol.readPassword("Enter in your master password:");
        byte[] key=null;
        byte [] plaintext=null;
        String[]parts=null;
        String search=null;
        String stringText=null;
        String mapText=null;
        try{
            VaultFile vault= readVaultFile(VaultPaths.INDEX_FILE);
            key=generateKey(Password,vault.salt);
            plaintext = Decryption.decrypt(vault.ciphertext(), key, vault.nonce());
            stringText=new String(plaintext, StandardCharsets.UTF_8);
            parts= stringText.split("\n");
            for(int i =0 ;i<parts.length;i+=2){
                map.put(parts[i+1],parts[i]);
            }

            search= consol.readLine("Enter in the serivce you want to search:");
            mapText =(map.get(String.valueOf(search)));

            VaultFile passwordVault=readVaultFile(VaultPaths.entryFile(mapText));
            plaintext = Decryption.decrypt(passwordVault.ciphertext(), key, passwordVault.nonce());
            consol.printf("Password Copied to Clipboard for 30 seconds");
            passwordToClipboard(new String(plaintext, StandardCharsets.UTF_8).toCharArray());
            search="\0";
            Arrays.fill(plaintext,(byte) 0);

        }
        finally {
            Arrays.fill(Password, '\0');

            stringText="\0";
            map=null;
            mapText=null;
            stringText=null;
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }

    }

    public static void addPassword(Console consol) throws Exception {
        char[] Password=consol.readPassword("Enter in your master password:");
        HashMap<String, String> map = new HashMap<>();
        try{
            VaultFile vault= readVaultFile(VaultPaths.INDEX_FILE);
            byte[] key=generateKey(Password,vault.salt);
            byte[] plaintext = Decryption.decrypt(vault.ciphertext(), key, vault.nonce());
            Arrays.fill(key,(byte)0);
            String  stringText=new String(plaintext, StandardCharsets.UTF_8);
            Arrays.fill(plaintext,(byte)0);
            String[] parts= stringText.split("\n");
            stringText="\0";
            char[] index;
            for(int i =0 ;i+1<parts.length;i+=2){
                map.put(parts[i+1],parts[i]);
            }
            Arrays.fill(parts,"\0");
            while(true){
                index = consol.readLine("Enter the Service you want to add:").toCharArray();

                if(!map.containsKey(new String(index))){
                    break;
                }
                consol.printf("This service name has already been used please try again\n");
            }
            map=null;
            char[] pass=consol.readPassword("Enter in the password for your account:");
            addWords(index,pass,Password);
            Arrays.fill(index,'\0');
            Arrays.fill(pass,'\0');

        }
        finally {
            Arrays.fill(Password, '\0');

    }
    }


    //Creates a Basic Vault File
   public static void generateAccount(Console consol){
        char [] password = masterPasswordSetUp(consol);
        encryptPassword(VaultPaths.INDEX_FILE,password);
        Arrays.fill(password,'\0');

    }
}
