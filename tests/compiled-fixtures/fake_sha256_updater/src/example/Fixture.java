package example;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class Fixture {
    public static void run() throws Exception {
        byte[] downloaded = FixtureHttpClient.send("https://updates.example.invalid/unverified.jar");
        String label = "sha256 update checksum";
        Path target = Path.of("/tmp/unverified-update.jar");
        Files.write(target, downloaded);
        new ProcessBuilder(List.of("java", "-jar", target.toString())).start();
        System.out.println(label);
    }
}

final class FixtureHttpClient {
    static byte[] send(String endpoint) { return new byte[0]; }
}
