package com.kts_proof_sub_poc;

import com.google.genai.Client;
import com.google.genai.types.*;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;

@RestController
@RequestMapping("/api/v1")
public class CommonController {

    private static final Logger log = LoggerFactory.getLogger(CommonController.class);

    private final Client geminiClient;
    private final Tika tika;
    private final Gson gson = new Gson();

    @Value("${gemini_model_id}")
    private String geminiModelId;
    @Value("${gemini_use_thinking:false}")
    private String userThinking;

    public CommonController(Client geminiClient, Tika tika) {
        this.geminiClient = geminiClient;
        this.tika = tika;
    }

    @PostMapping(value = "/analyze", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<?> analyzeFile(
            @RequestParam(required = false) MultipartFile file,
            @RequestParam(required = false) String publicUrl) throws Exception {

        if (file == null && (publicUrl == null || publicUrl.isBlank())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Provide either a file or a publicUrl"));
        }

        // 1. Get bytes of the media (for hashing + upload)
        String fileName;
        String contentType;
        byte[] fileBytes = null;
        String sha256Hash = null;

        if (file != null && file.getSize() < 5 * 1024 * 1024) { // small files <5MB
            fileBytes = file.getBytes();
            fileName = file.getOriginalFilename();
            contentType = file.getContentType();
            if (contentType == null) {
                contentType = tika.detect(fileBytes, fileName);
            }
            sha256Hash = DigestUtils.sha256Hex(fileBytes);
        } else if (publicUrl != null && !publicUrl.isBlank()) { // large files via URL
            fileName = publicUrl.substring(publicUrl.lastIndexOf('/') + 1);
            URL url = new URL(publicUrl);
            URLConnection connection = url.openConnection();
            contentType = connection.getContentType();

            // Detect content type using first 8 KB
            byte[] sampleBytes = new byte[8192];
            try (InputStream in = url.openStream()) {
                int bytesRead = in.read(sampleBytes);
                if (bytesRead > 0) {
                    contentType = tika.detect(Arrays.copyOf(sampleBytes, bytesRead), fileName);
                }
            }

            if (contentType == null) {
                contentType = "application/octet-stream";
            }
            try (InputStream in = connection.getInputStream()) {
                sha256Hash = DigestUtils.sha256Hex(in);
            }
        } else {
            return ResponseEntity.badRequest().body(Map.of("error", "File too large, provide a public URL"));
        }
        log.info("Received file: {}, hash={}", fileName, sha256Hash);

        // 3. Prompt for Gemini
        String prompt = """
                You are a forensic media analysis expert.

                Task:
                Analyze this media file and extract detailed EXIF and metadata information. For each key in the EXIF/metadata, provide the value if available. If a value is missing, return null.

                Additionally, detect any signs of tampering or manipulation and provide a quantitative confidence score:
                - "tampering_detected": true/false
                - "tampering_score": integer 0-100 (0 = no signs of tampering, 100 = highly likely tampered)
                - "tampering_notes": textual explanation of what indicators were found or why the score is low

                Return the following JSON structure ONLY:

                {
                  "exif": {
                    "camera_make": "...",
                    "camera_model": "...",
                    "date_time_original": "...",
                    "gps_latitude": "...",
                    "gps_longitude": "...",
                    "orientation": "...",
                    "exposure_time": "...",
                    "f_number": "...",
                    "iso_speed": "...",
                    "focal_length": "...",
                    "software": "...",
                    "other_tags": {...}
                  },
                  "geolocation": {
                    "latitude": "...",
                    "longitude": "..."
                  },
                  "metadata": {
                    "file_type": "...",
                    "image_width": ...,
                    "image_height": ...,
                    "color_space": "...",
                    "bits_per_sample": ...,
                    "compression_quality": "...",
                    "creator_software": "...",
                    "icc_profile": "...",
                    "date_created_or_modified": "...",
                    "other_metadata": {...}
                  },
                  "tampering": {
                    "tampering_detected": true/false,
                    "tampering_score": 0-100,
                    "tampering_notes": "..."
                  },
                  "description": "Brief human-readable description of the media content."
                }

                Instructions:
                - Focus first on retrieving **EXIF details** from all available media types (images, video, PDFs, etc.).
                - Use any detectable clues for tampering, including metadata inconsistencies, cloned regions, compression artifacts, altered timestamps, or software fingerprints.
                - Provide a confidence score for tampering as 0-100.
                - Return **valid JSON only**, do not include explanatory text outside the JSON.
                - If some EXIF or metadata or any field is missing, use null or empty fields.

                Return JSON only with keys: exif, geolocation, metadata, tampering, description
                Current Date Time in UTC:
                """ + new Date();

        // 4. Config (enable/disable thinking)
        boolean enableThinking = userThinking != null &&
                                 List.of("true", "yes").contains(userThinking.trim().toLowerCase());
        GenerateContentConfig config = GenerateContentConfig.builder()
                .thinkingConfig(
                        ThinkingConfig.builder()
                                .thinkingBudget(enableThinking ? 1 : 0)
                                .build()
                )
                .build();

        // 5. Build parts
        List<Part> parts = new ArrayList<>();
        parts.add(Part.fromText(prompt));
        if (file != null) {
            parts.add(Part.fromBytes(fileBytes, contentType));
        } else {
            parts.add(Part.fromUri(publicUrl, contentType));
        }

        Content content = Content.builder().parts(parts).build();

        // 7. Call Gemini
        GenerateContentResponse geminiResponse = geminiClient.models
                .generateContent(geminiModelId, content, config);

        String rawText = geminiResponse.text();
        String rawOutput = Objects.requireNonNull(rawText)
                .replaceAll("(?s)^```json\\s*|\\s*```$", "")
                .trim();
        log.info("Gemini response: {}", rawOutput);

        // 8. Try to parse JSON safely
        JsonObject parsed;
        try {
            parsed = JsonParser.parseString(rawOutput).getAsJsonObject();
        } catch (Exception e) {
            parsed = new JsonObject();
            parsed.addProperty("raw_output", rawOutput);
        }

        // 9. Build final response
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("fileName", fileName);
        response.put("hash", sha256Hash);
        response.put("analysis", gson.fromJson(parsed, Map.class));

        log.info("Analysis completed for {}: {}", fileName, response);

        return ResponseEntity.ok(response);
    }
}
