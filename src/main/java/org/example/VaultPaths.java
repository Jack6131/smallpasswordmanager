package org.example;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class VaultPaths {
    private VaultPaths() {}

    private static final Path VAULT_DIR =
            Path.of(System.getProperty("user.home"), ".vault");

    public static final Path INDEX_FILE =
            VAULT_DIR.resolve("index.dat");

    public static final Path ENTRIES_DIR =
            VAULT_DIR.resolve("entries");

    public static Path entryFile(String id) {
        return ENTRIES_DIR.resolve(id + ".dat");
    }

    public static void initializeDirectories() throws IOException {
        Files.createDirectories(ENTRIES_DIR);
    }

    public static boolean exists() {
        return Files.isRegularFile(INDEX_FILE);
    }
}
