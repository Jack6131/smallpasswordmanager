package org.example;
import java.io.Console;
import java.nio.file.Files;

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
            case "rmv"-> GenerateAccount.removePassword(consol);
            default -> {
                System.err.println("Unknown command: " + args[0]);
                System.exit(1);
            }
        }

    }
}