import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.awt.*;
import java.awt.image.BufferedImage;
import javax.crypto.SecretKey;
import javax.imageio.ImageIO;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class Student {
    private final static String publicKeyPath = "/etc/wateacher/public_key.pem";
    private static PublicKey publicKey;

    public static void main(String[] args) throws Exception {
        int port = 7654;

        BufferedImage screenFullImage = new Robot().createScreenCapture(new Rectangle(Toolkit.getDefaultToolkit().getScreenSize()));

        publicKey = loadPublicKey();

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/screenshot", new ScreenshotHandler());
        server.setExecutor(null);
        server.start();
    }

    static class ScreenshotHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");

            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                // Responder a preflight request CORS
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if ("GET".equals(exchange.getRequestMethod())) {
                try {
                    BufferedImage screenFullImage = new Robot().createScreenCapture(new Rectangle(Toolkit.getDefaultToolkit().getScreenSize()));

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ImageIO.write(screenFullImage, "png", baos);
                    byte[] imageBytes = baos.toByteArray();

                    // 3. Generar clave AES
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(256);
                    SecretKey aesKey = keyGen.generateKey();

                    // 4. Cifrar imagen con AES
                    Cipher aesCipher = Cipher.getInstance("AES");
                    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                    byte[] encryptedImage = aesCipher.doFinal(imageBytes);

                    // 5. Cifrar clave AES con RSA
                    Cipher rsaCipher = Cipher.getInstance("RSA");
                    rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
                    byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());


                    ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
                    DataOutputStream dos = new DataOutputStream(responseStream);
                    dos.writeInt(encryptedKey.length);
                    dos.write(encryptedKey);
                    dos.writeInt(encryptedImage.length);
                    dos.write(encryptedImage);

                    byte[] responseBytes = responseStream.toByteArray();
                    exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
                    exchange.sendResponseHeaders(200, responseBytes.length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(responseBytes);
                    os.close();
                } catch (Exception e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1);
                }
            } else {
                    exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static PublicKey loadPublicKey() throws Exception {
        String keyString = Files.readString(Path.of(publicKeyPath))

                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(keyString)));
    }
}
