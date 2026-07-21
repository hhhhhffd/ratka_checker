package example;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

public final class Fixture {
    private static final byte[] EXPECTED = new byte[] {1, 2, 3, 4};

    public static void run() throws Exception {
        byte[] downloaded = FixtureHttpClient.send("https://updates.example.invalid/verified.jar");
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(downloaded);
        if (!Arrays.equals(digest, EXPECTED)) {
            throw new SecurityException("invalid update");
        }
        Path target = Path.of("/tmp/verified-update.jar");
        Files.write(target, downloaded);
        new ProcessBuilder(List.of("java", "-jar", target.toString())).start();
    }
}

final class FixtureHttpClient {
    static byte[] send(String endpoint) { return new byte[0]; }
}
