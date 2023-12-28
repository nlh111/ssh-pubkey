import com.sun.net.httpserver.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class SimpleHttpServer {

    public static void main(String[] args) throws Exception {
 // Load the keystore
        char[] password = "nlh1997".toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream("./cert/server.jks");
        ks.load(fis, password);

        // Set up the key manager factory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, password);

        // Set up the trust manager factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);

        // Set up the HTTPS context and parameters
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        HttpsServer server = HttpsServer.create(new InetSocketAddress(8000), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        server.createContext("/sign", new MyHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            if ("POST".equals(t.getRequestMethod())) {
                try {
                    // Get http post headers of the request and then get the sign key
                    Headers headers = t.getRequestHeaders();
                    String domain = headers.getFirst("Domain");
                    String digest = headers.getFirst("Digest");
                    String keyPath = "./Keys/" + domain + "_KEY.der";

                    // Generate the private key
                    byte[] keyBytes = Files.readAllBytes(Paths.get(keyPath));
                    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                    KeyFactory kf = KeyFactory.getInstance("EC");
                    PrivateKey privateKey = kf.generatePrivate(spec);

                    // Sign the digest
                    byte[] toBeSigned = Base64.getDecoder().decode(digest);
                    Signature ecdsaSign = Signature.getInstance("NONEwithECDSA");
                    ecdsaSign.initSign(privateKey);
                    ecdsaSign.update(toBeSigned);
                    byte[] signature = ecdsaSign.sign();

                    // handle POST request
                    String response = Base64.getEncoder().encodeToString(signature);
                    t.sendResponseHeaders(200, response.length());
                    OutputStream os = t.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } catch (Exception e) {
                    System.out.println("Exception: " + e.getMessage());
                }
            }
        }
    }
}