import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.awt.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class Teacher {
    private final static String publicKeyPath = "/etc/wateacher/public_key.pem";
    private static PublicKey publicKey;

    public static void main(String[] args) throws Exception {
        int port = 7654;

        publicKey = loadPublicKey();

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/screenshot", new ScreenshotHandler());
        server.setExecutor(null);
        server.start();
    }
    
    static class ScreenshotHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                try {
                    Rectangle screenRect = new Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
                    BufferedImage screenFullImage = new Robot().createScreenCapture(screenRect);

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ImageIO.write(screenFullImage, "png", baos);
                    byte[] imageBytes = baos.toByteArray();

                    byte[] encryptedImage = encryptData(imageBytes, publicKey);

                    exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
                    exchange.sendResponseHeaders(200, encryptedImage.length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(encryptedImage);
                    os.close();
                } catch (Exception e) {
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

    private static byte[] encryptData(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}
