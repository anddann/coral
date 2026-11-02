package VersionTools;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.apache.maven.artifact.versioning.VersionRange;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Application {

    public static void main(String[] args) throws IOException {
        int port = 8080;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException ignored) {}
        }
        String envPort = System.getenv("PORT");
        if (envPort != null && !envPort.isEmpty()) {
            try {
                port = Integer.parseInt(envPort);
            } catch (NumberFormatException ignored) {}
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/sort", new SortHandler());
        server.createContext("/checkinrange", new CheckRangeHandler());
        server.createContext("/compare", new CompareHandler());
        server.createContext("/health", new HealthHandler());
        server.setExecutor(null);

        System.out.println("[INFO] Maven SemVer service started on port " + port);
        server.start();
    }

    private static class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            sendResponse(exchange, 200, "OK");
        }
    }

    private static class SortHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "Method Not Allowed");
                return;
            }

            String body = readBody(exchange.getRequestBody());
            String versionlistStr = null;

            Map<String, String> params = parseFormData(body);
            if (params.containsKey("versionlist")) {
                versionlistStr = params.get("versionlist");
            } else {
                versionlistStr = body.trim();
            }

            if (versionlistStr == null || versionlistStr.isEmpty()) {
                sendResponse(exchange, 200, "");
                return;
            }

            String[] rawTokens = versionlistStr.split("\\|");
            List<String> list = new ArrayList<>();
            for (String t : rawTokens) {
                if (t != null && !t.isEmpty()) {
                    list.add(t);
                }
            }

            list.sort(Comparator.comparing(ComparableVersion::new));
            String result = String.join("|", list);
            sendResponse(exchange, 200, result);
        }
    }

    private static class CheckRangeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> queryParams = parseQueryParams(exchange.getRequestURI().getRawQuery());
            String version = queryParams.get("version");
            String range = queryParams.get("range");

            if (version == null || range == null) {
                sendResponse(exchange, 400, "Missing 'version' or 'range'");
                return;
            }

            boolean inRange = false;
            try {
                VersionRange vr = VersionRange.createFromVersionSpec(range);
                inRange = vr.containsVersion(new DefaultArtifactVersion(version));
            } catch (Exception e) {
                System.err.println("[WARN] Invalid range spec: " + range + " (" + e.getMessage() + ")");
            }

            sendResponse(exchange, 200, inRange ? "true" : "false");
        }
    }

    private static class CompareHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> queryParams = parseQueryParams(exchange.getRequestURI().getRawQuery());
            String v1 = queryParams.get("v1");
            String v2 = queryParams.get("v2");
            if (v1 == null || v2 == null) {
                sendResponse(exchange, 400, "Missing 'v1' or 'v2'");
                return;
            }
            ComparableVersion cv1 = new ComparableVersion(v1);
            ComparableVersion cv2 = new ComparableVersion(v2);
            sendResponse(exchange, 200, String.valueOf(cv1.compareTo(cv2)));
        }
    }

    private static String readBody(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
        return out.toString(StandardCharsets.UTF_8.name());
    }

    private static Map<String, String> parseFormData(String body) {
        Map<String, String> map = new HashMap<>();
        if (body == null || body.isEmpty()) return map;
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                try {
                    String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name());
                    map.put(key, value);
                } catch (Exception ignored) {}
            }
        }
        return map;
    }

    private static Map<String, String> parseQueryParams(String rawQuery) {
        Map<String, String> map = new HashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) return map;
        String[] pairs = rawQuery.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                try {
                    String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name());
                    map.put(key, value);
                } catch (Exception ignored) {}
            }
        }
        return map;
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
