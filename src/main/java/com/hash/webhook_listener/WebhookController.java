package com.hash.webhook_listener;

import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

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
            // Calculate HMAC-SHA1 of the request body
            byte[] calculated = calculateHmacSha1(SECRET_KEY.getBytes(), body.getBytes());
            String calculatedHex = bytesToHex(calculated);

            if (calculatedHex.equalsIgnoreCase(signatureHeader)) {
                // ✅ Valid signature
                JSONObject responseJson = new JSONObject();
                responseJson.put("rrn", rrn);
                responseJson.put("status", "SUCCESS");

                return ResponseEntity.ok()
                        .header("Content-Type", "application/json")
                        .body(responseJson.toString());

            } else {
                // ❌ Invalid signature
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

    //validate path
    @PostMapping("/validate")
    public ResponseEntity<String> validateBill(@RequestBody String body) {
        try {
            JSONObject payload = new JSONObject(body);
            String billRef = payload.optString("billRef", "");
            double amount = payload.optDouble("amount", 0.00);
            String amountStr = String.format("%.2f", amount);

            // ✅ Always return success response by default
            JSONObject success = new JSONObject();
            success.put("billRef", billRef);
            success.put("amount", amountStr);
            success.put("billId", "40651440"); // Static or can be generated dynamically
            success.put("status", "valid");
            success.put("statusDescription", "");

            return ResponseEntity.ok()
                    .header("Content-Type", "application/json")
                    .body(success.toString());

        } catch (Exception e) {
            LOGGER.error("Error processing /validate request: {}", e.getMessage());
            JSONObject errorResponse = new JSONObject();
            errorResponse.put("status", "error");
            errorResponse.put("statusDescription", "Invalid request format");

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(errorResponse.toString());
        }
    }



    private static byte[] calculateHmacSha1(byte[] key, byte[] data) throws Exception {
        SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);
        return mac.doFinal(data);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
