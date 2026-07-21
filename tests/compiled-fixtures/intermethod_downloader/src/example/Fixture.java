package example;

import java.nio.file.Files;
import java.nio.file.Path;

public final class Fixture {
    public static void run() throws Exception {
        byte[] downloaded = download();
        saveAndLaunch(downloaded);
    }

    private static byte[] download() {
        byte[] value = FixtureHttpClient.send("https://updates.example.invalid/intermethod.jar");
        return value;
    }

    private static void saveAndLaunch(byte[] downloaded) throws Exception {
        Path target = Path.of("/tmp/intermethod-update.jar");
        Files.write(target, downloaded);
        new ProcessBuilder("java", "-jar", target.toString()).start();
    }
}

final class FixtureHttpClient {
    static byte[] send(String endpoint) { return new byte[0]; }
}
