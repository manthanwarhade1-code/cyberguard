
package com.cyberguard.cyberguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URI;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.*;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class CyberguardApplication {

    public static void main(String[] args) {
        SpringApplication.run(CyberguardApplication.class, args);
    }

    private final List<ScanResult> history =
            new CopyOnWriteArrayList<>();

    record ScanResult(
            String type,
            String target,
            String status,
            String risk,
            String details,
            String time
    ) {}

    private ScanResult save(
            String type, String target,
            String status, String risk, String details) {

        ScanResult result = new ScanResult(
                type, target, status, risk,
                details, LocalDateTime.now().toString()
        );

        history.add(0, result);
        return result;
    }

    // 1. URL SCANNER
    @PostMapping("/scan/url")
    public ScanResult scanUrl(@RequestBody Map<String, String> data) {

        String url = data.getOrDefault("url", "").trim();

        if (url.isEmpty()) {
            throw new IllegalArgumentException("Enter a URL");
        }

        String lower = url.toLowerCase();
        List<String> reasons = new ArrayList<>();

        try {
            URI uri = URI.create(
                    lower.matches("^[a-z][a-z0-9+.-]*://.*")
                    ? lower : "https://" + lower
            );

            String host = uri.getHost();

            if (host == null || !host.contains(".")) {
                reasons.add("Invalid or unusual domain structure");
            }

            if (lower.contains("@")) {
                reasons.add("Contains @ symbol");
            }

            if (lower.contains("login") ||
                lower.contains("verify") ||
                lower.contains("free-gift") ||
                lower.contains("password")) {
                reasons.add("Contains suspicious keywords");
            }

            if (url.length() > 100) {
                reasons.add("Unusually long URL");
            }

            if (host != null &&
                host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                reasons.add("Uses an IP address instead of a domain");
            }

            if (host != null &&
                (host.contains("bit.ly") ||
                 host.contains("tinyurl.com"))) {
                reasons.add("Uses a URL shortening service");
            }

        } catch (Exception e) {
            reasons.add("URL format could not be validated");
        }

        String status = reasons.isEmpty()
                ? "NO OBVIOUS THREAT"
                : reasons.size() >= 3
                ? "HIGH RISK" : "SUSPICIOUS";

        return save(
                "URL",
                url,
                status,
                status,
                reasons.isEmpty()
                ? "No suspicious patterns found by basic checks."
                : String.join(", ", reasons)
        );
    }

    // 2. FILE SCANNER
    @PostMapping("/scan/file")
    public ScanResult scanFile(
            @RequestParam("file") MultipartFile file)
            throws Exception {

        if (file.isEmpty()) {
            throw new IllegalArgumentException("Empty file");
        }

        if (file.getSize() > 10 * 1024 * 1024) {
            throw new IllegalArgumentException(
                    "Maximum file size is 10 MB");
        }

        String name = file.getOriginalFilename();

        if (name == null) name = "unknown";

        String hash = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256")
                        .digest(file.getBytes())
        );

        String lower = name.toLowerCase();
        List<String> reasons = new ArrayList<>();

        if (lower.matches(".*\\.(exe|bat|cmd|scr|vbs|ps1)$")) {
            reasons.add("Executable or script file type");
        }

        if (lower.matches(".*\\.(pdf|jpg|png|docx?)\\.(exe|bat|js)$")) {
            reasons.add("Double file extension detected");
        }

        String status = reasons.isEmpty()
                ? "NO OBVIOUS THREAT"
                : "SUSPICIOUS";

        return save(
                "FILE",
                name,
                status,
                status,
                "SHA-256: " + hash + ". " +
                (reasons.isEmpty()
                ? "No suspicious extension pattern found. This is not a malware verdict."
                : String.join(", ", reasons))
        );
    }

    // 3. NETWORK LOG SCANNER
    @PostMapping("/scan/network")
    public ScanResult scanNetwork(@RequestBody String logs) {

        if (logs == null || logs.isBlank()) {
            throw new IllegalArgumentException("Enter network logs");
        }

        Pattern ipPattern = Pattern.compile(
                "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
        );

        Matcher matcher = ipPattern.matcher(logs);

        Map<String, Integer> ipCounts = new HashMap<>();

        while (matcher.find()) {
            String ip = matcher.group();
            ipCounts.merge(ip, 1, Integer::sum);
        }

        List<String> reasons = new ArrayList<>();

        ipCounts.forEach((ip, count) -> {
            if (count >= 6) {
                reasons.add(
                        "Repeated IP activity: " + ip +
                        " (" + count + " occurrences)"
                );
            }
        });

        String lower = logs.toLowerCase();

        if (lower.contains("port 4444") ||
            lower.contains("port=4444") ||
            lower.contains("port:4444")) {
            reasons.add("Unusual port 4444 activity");
        }

        if (lower.contains("port 23") ||
            lower.contains("port=23")) {
            reasons.add("Telnet port activity detected");
        }

        String status = reasons.isEmpty()
                ? "NO OBVIOUS THREAT"
                : "SUSPICIOUS";

        return save(
                "NETWORK",
                "Uploaded network log",
                status,
                status,
                "IP addresses analyzed: " + ipCounts.size() +
                ". " +
                (reasons.isEmpty()
                ? "No configured suspicious patterns found."
                : String.join(", ", reasons))
        );
    }

    // 4. SCAN HISTORY
    @GetMapping("/history")
    public List<ScanResult> getHistory() {
        return history;
    }

    @DeleteMapping("/history")
    public Map<String, String> clearHistory() {
        history.clear();
        return Map.of("message", "History cleared");
    }
}
