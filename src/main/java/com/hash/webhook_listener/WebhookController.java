package com.hash.webhook_listener;

import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Base64;

@RestController
@RequestMapping("/webhook")
public class WebhookController {

    // Change this to your fintech preshared password
    private static final String SECRET_KEY = "123456";
    private static final Logger LOGGER = LoggerFactory.getLogger(WebhookController.class);

    @PostMapping
    public ResponseEntity<String> handleWebhook(
            @RequestBody String body,
            @RequestHeader(value = "X-Signature", required = false) String signatureHeader) {

        JSONObject payload;
        String rrn = "UNKNOWN";

        try {
            payload = new JSONObject(body);
            rrn = payload.optString("rrn", "UNKNOWN");
        } catch (Exception e) {
            LOGGER.error("Failed to parse request body JSON: {}", e.getMessage());
            JSONObject error = new JSONObject()
                    .put("rrn", rrn)
                    .put("status", "ERROR");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(error.toString());
        }

        if (signatureHeader == null) {
            JSONObject error = new JSONObject()
                    .put("rrn", rrn)
                    .put("status", "ERROR")
                    .put("message", "Missing X-Signature header");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(error.toString());
        }

        try {
            // Generate HMAC-SHA1 hash using base64-encoded payload (Python equivalent)
            String calculatedHex = generateHmacSha1Base64(SECRET_KEY, body);

            if (calculatedHex.equalsIgnoreCase(signatureHeader)) {
                // Valid signature
                JSONObject responseJson = new JSONObject();
                responseJson.put("rrn", rrn);
                responseJson.put("status", "SUCCESS");

                return ResponseEntity.ok()
                        .header("Content-Type", "application/json")
                        .body(responseJson.toString());

            } else {
                // Invalid signature
                JSONObject insecure = new JSONObject();
                insecure.put("rrn", rrn);
                insecure.put("status", "INSECURE");

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .header("Content-Type", "application/json")
                        .body(insecure.toString());
            }

        } catch (Exception e) {
            LOGGER.error("Unexpected error: {}", e.getMessage());

            JSONObject error = new JSONObject();
            error.put("rrn", rrn);
            error.put("status", "ERROR");

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .header("Content-Type", "application/json")
                    .body(error.toString());
        }
    }

    /**
     * Generates an HMAC-SHA1 hash of the Base64-encoded payload using SECRET_KEY.
     * This replicates the Python logic:
     * base64_encoded_payload = base64.b64encode(data.encode("utf-8"))
     * mac = hmac.new(pwd.encode(), base64_encoded_payload, sha1)
     * hex_string = mac.hexdigest()
     */
    private static String generateHmacSha1Base64(String key, String data) throws Exception {
        // Base64 encode the payload
        String base64EncodedPayload = Base64.getEncoder().encodeToString(data.getBytes("UTF-8"));

        // Create HMAC-SHA1 using the secret key
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);

        // Compute the HMAC of the Base64-encoded data
        byte[] rawHmac = mac.doFinal(base64EncodedPayload.getBytes("UTF-8"));

        // Convert to lowercase hex string (same as Python hexdigest)
        StringBuilder sb = new StringBuilder();
        for (byte b : rawHmac) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
