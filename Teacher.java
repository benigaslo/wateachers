import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Teacher {
    public static final String privateKeyPath = "/etc/wateacher/private_key.pem";
    public static String privateKey;

    public static void main(String[] args) throws Exception {
        int port = 7655;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        privateKey = loadPrivateKey();

        server.createContext("/", new HtmlHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Servidor HTTP corriendo en http://localhost:" + port);
    }

    static class HtmlHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {

            String content = Files.readString(Path.of("index.html"));
            content = content.replace("%%%keyText%%%",privateKey);
            byte[] contentBytes = content.getBytes();
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, contentBytes.length);
            OutputStream os = exchange.getResponseBody();
            os.write(contentBytes);
            os.close();
        }
    }

    private static String loadPrivateKey() throws Exception {
        return Files.readString(Path.of(privateKeyPath))
//                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
//                .replaceAll("-----END PUBLIC KEY-----", "")
//                .replaceAll("\n","")
//                .replaceAll("\\s", "")
                ;
//
//        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(keyString)));
    }
}
