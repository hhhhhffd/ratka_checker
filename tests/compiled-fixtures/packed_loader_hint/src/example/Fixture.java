package example;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.zip.ZipInputStream;

/** Static-only fixture: never execute. Independent capabilities are not a proven chain. */
public final class Fixture {
    public static InputStream run(String location) throws Exception {
        return Http.fetch(location);
    }

    public static void unpack(InputStream input, String destination) throws Exception {
        try (ZipInputStream zip = new ZipInputStream(input);
             FileOutputStream output = new FileOutputStream(destination)) {
            zip.getNextEntry();
            zip.transferTo(output);
        }
    }

    public static void launch() throws Exception {
        new ProcessBuilder("java", "-version").start();
    }
}

final class Http {
    static InputStream fetch(String location) throws Exception {
        return new URL(location).openStream();
    }
}
