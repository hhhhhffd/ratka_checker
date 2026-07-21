package example;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class Fixture {
    public static void run() throws Exception {
        byte[] downloaded = FixtureHttpClient.send("https://updates.example.invalid/list.jar");
        Path target = Path.of("/tmp/list-update.jar");
        Files.write(target, downloaded);
        ProcessBuilder builder = new ProcessBuilder(List.of("java", "-jar", target.toString()));
        builder.start();
    }
}

final class FixtureHttpClient {
    static byte[] send(String endpoint) { return new byte[0]; }
}
