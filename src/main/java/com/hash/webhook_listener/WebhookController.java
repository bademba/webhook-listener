package com.hash.webhook_listener;

import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



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

        if (signatureHeader == null) {
            JSONObject error = new JSONObject().put("error", "Missing X-Signature header");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(error.toString());
        }

        try {
            // Calculate HMAC-SHA1 of the request body
            byte[] calculated = calculateHmacSha1(SECRET_KEY.getBytes(), body.getBytes());
            String calculatedHex = bytesToHex(calculated);

            if (calculatedHex.equalsIgnoreCase(signatureHeader)) {
                // Parse incoming JSON to extract rrn
                JSONObject payload = new JSONObject(body);
                LOGGER.info(String.format("REQUEST::: %s", payload));

                String rrn = payload.optString("rrn", "UNKNOWN");

                // Build success JSON response
                JSONObject responseJson = new JSONObject();
                responseJson.put("rrn", rrn);
                responseJson.put("status", "SUCCESS");
                LOGGER.info(String.format("RESPONSE::: %s", responseJson));

                return ResponseEntity.ok()
                        .header("Content-Type", "application/json")
                        .body(responseJson.toString());

            } else {
                JSONObject invalid = new JSONObject().put("status", "INVALID_SIGNATURE");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .header("Content-Type", "application/json")
                        .body(invalid.toString());
            }
        } catch (Exception e) {
            JSONObject error = new JSONObject().put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .header("Content-Type", "application/json")
                    .body(error.toString());
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
