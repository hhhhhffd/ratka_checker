package example;

import java.nio.file.Files;
import java.nio.file.Path;

public final class Fixture {
    public static byte[] readConfig() throws Exception {
        return Files.readAllBytes(Path.of("config/settings.json"));
    }
}
