package org.example;
import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static org.example.GenerateAccount.addWords;
import static org.example.GenerateAccount.readVaultFile;

public class Main {
    private static final Path VAULT = Path.of("vault.dat");


    public static void start(Console console,GenerateAccount start) throws Exception {
        if (Files.exists(VAULT)) {
            console.printf("Existing vault found.%n");
            start.signIn(console);
        } else {
            console.printf("No vault found. Creating one.%n");
            start.generateAccount(console);
        }
    }
    public static void main(String[] args) throws Exception {
        Console consol= System.console();
        GenerateAccount start= new GenerateAccount();
        start(consol,start);
    }
}