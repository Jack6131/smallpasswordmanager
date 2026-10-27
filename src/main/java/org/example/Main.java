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



    public static boolean start(Console console) throws Exception {
        if (Files.exists(VaultPaths.INDEX_FILE)) {
        } else {
            console.printf("No vault found. Creating one.%n");
            GenerateAccount.generateAccount(console);
            return true;
        }
        return false;
    }
    public static void main(String[] args) throws Exception {
        Console consol= System.console();
        if(start(consol)){
            System.exit(1);
        }

        switch (args[0]) {
            case "add" -> GenerateAccount.addPassword(consol);
            case "get" -> GenerateAccount.getPassword(consol);
            default -> {
                System.err.println("Unknown command: " + args[0]);
                System.exit(1);
            }
        }

    }
}