package com.kts_proof_sub_poc;

import com.google.genai.Client;
import com.google.genai.types.*;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.tika.Tika;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.sax.BodyContentHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.ContentHandler;

import java.io.*;
import java.io.File;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;

import com.drew.imaging.ImageMetadataReader;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

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
        String sha256Hash;
        InputStream inputStream;

        if (file != null) {
            fileName = file.getOriginalFilename();
            inputStream = new BufferedInputStream(file.getInputStream());
            inputStream.mark(Integer.MAX_VALUE); // allow reset
            contentType = file.getContentType();
            if (contentType == null) {
                contentType = tika.detect(inputStream, fileName);
                inputStream.reset();
            }
            sha256Hash = DigestUtils.sha256Hex(inputStream);
            inputStream.reset();
        } else {
            fileName = publicUrl.substring(publicUrl.lastIndexOf('/') + 1);
            URL url = new URL(publicUrl);
            URLConnection connection = url.openConnection();
            inputStream = new BufferedInputStream(connection.getInputStream());
            inputStream.mark(Integer.MAX_VALUE);

            contentType = connection.getContentType();
            if (contentType == null) {
                contentType = tika.detect(inputStream, fileName);
                inputStream.reset();
            }
            sha256Hash = DigestUtils.sha256Hex(inputStream);
            inputStream.reset();
        }

        log.info("Received file: {}, hash={}", fileName, sha256Hash);

        // --- Extract EXIF + Metadata ---
        Map<String, Map<String, String>> extracted = extract(inputStream, contentType, fileName);
        String extractedJson = gson.toJson(extracted);

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
                                      "description": "Brief human-readable description of the media content.",
                                      "detail":{
                                        "height": "...",
                                        "weight": "...",
                                        "age": "...",
                                        "type": "..."
                                      },
                                      "verify":{
                                      "isFileAccountForCarbonAccounting": true/false,
                                      "calculateCarbonFootPrint":"...",
                                      "sdgItFallsIn":"..."
                                      }
                                    }

                                    Instructions:
                                    - Focus first on retrieving **EXIF details** from all available media types (images, video, PDFs, etc.).
                                    - Use any detectable clues for tampering, including metadata inconsistencies, cloned regions, compression artifacts, altered timestamps, or software fingerprints.
                                    - Provide a confidence score for tampering as 0-100.
                                    - include 1 more key called detail and add height, weight, age, type of main element, if not sure then add assumption but mention is assumed.
                                    - include 1 more key called verify and check if the file account for carbon foot print calculations, and if yes calculate carbon foot print for that means find main element and find its carbon foot print, give detail like giving now but also key a number field direct number we get, and add sdg it falls under an percentage contribution for each sdg.
                                    - Return **valid JSON only**, do not include explanatory text outside the JSON.
                                    - If some EXIF or metadata or any field is missing, use null or empty fields.

                                    Return JSON only with keys: exif, geolocation, metadata, tampering, description
                                    Include all metadata and exif from local extraction also in response.
                                    Known Metadata (from local extraction):
                                """ + extractedJson + "\n\nCurrent Date Time in UTC: " + new Date();

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
            parts.add(Part.fromBytes(file.getBytes(), contentType));
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
        response.put("local_extraction", extracted);
        response.put("analysis", gson.fromJson(parsed, Map.class));

        log.info("Analysis completed for {}: {}", fileName, response);

        return ResponseEntity.ok(response);
    }

    private static final Set<String> IMAGE_TYPES = Set.of("image/jpeg", "image/png", "image/tiff", "image/webp");
    private static final Set<String> TEMP_FILE_IGNORE_KEYS = Set.of(
            "File Name",
            "File Modified Date",
            "Content Identifier",
            "X-TIKA:Parsed-By",
            "X-TIKA:Parsed-By-Full-Set"
    );

    public static Map<String, Map<String, String>> extract(InputStream inputStream,
                                                           String contentType,
                                                           String fileName) throws Exception {
        Map<String, Map<String, String>> result = new HashMap<>();
        result.put("exif", new LinkedHashMap<>());
        result.put("metadata", new LinkedHashMap<>());

        if (contentType == null) contentType = "application/octet-stream";

        // ---- IMAGES: Use metadata-extractor ----
        if (IMAGE_TYPES.contains(contentType.toLowerCase())) {
            inputStream.mark(Integer.MAX_VALUE); // allow reset if needed
            Metadata metadata = ImageMetadataReader.readMetadata(inputStream);

            for (Directory dir : metadata.getDirectories()) {
                for (Tag tag : dir.getTags()) {
                    String tagName = tag.getTagName();
                    String tagValue = tag.getDescription();
                    if (TEMP_FILE_IGNORE_KEYS.contains(tagName)) {
                        continue;
                    }
                    result.get("exif").put(tagName, tagValue);
                }
            }
            inputStream.reset(); // rewind for Tika
        }

        // ---- GENERAL: Use Tika ----
        inputStream.reset(); // rewind for Tika
        org.apache.tika.metadata.Metadata tikaMetadata = new org.apache.tika.metadata.Metadata();
        ContentHandler handler = new BodyContentHandler(-1);
        AutoDetectParser parser = new AutoDetectParser();
        parser.parse(inputStream, handler, tikaMetadata);


        for (String name : tikaMetadata.names()) {
            String value = tikaMetadata.get(name);
            if (value != null && !value.isBlank()) {
                if (TEMP_FILE_IGNORE_KEYS.contains(name)) {
                    continue; // ignore metadata from temp files
                }
                result.get("metadata").put(name, value);
            }
        }

        return result;
    }

//    private static File streamToTempFile(InputStream input, String fileName) throws IOException {
//        File temp = File.createTempFile("upload_", "_" + fileName);
//        try (OutputStream out = new FileOutputStream(temp)) {
//            input.transferTo(out);
//        }
//        return temp;
//    }

    @PostMapping(value = "/analyze/proof", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<?> analyzeFile(
            @RequestParam(required = false) MultipartFile file,
            @RequestParam(required = false) MultipartFile file2,
            @RequestParam(required = false) String publicUrl,
            @RequestParam(required = false) String inputPrompt,
            @RequestParam(required = false, defaultValue = "0") Integer quantity,
            @RequestParam(required = false, defaultValue = "pieces") String units) throws Exception {

        if (file == null && (publicUrl == null || publicUrl.isBlank())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Provide either a file or a publicUrl"));
        }

        // 1. Get bytes of the media (for hashing + upload)
        String fileName;
        String contentType;
        String sha256Hash;
        InputStream inputStream;
        String fileName2 = null;
        String contentType2 = null;
        String sha256Hash2 = null;
        InputStream inputStream2 = null;

        if (file != null) {
            fileName = file.getOriginalFilename();
            inputStream = new BufferedInputStream(file.getInputStream());
            inputStream.mark(Integer.MAX_VALUE); // allow reset
            contentType = file.getContentType();
        } else {
            fileName = publicUrl.substring(publicUrl.lastIndexOf('/') + 1);
            URL url = new URL(publicUrl);
            URLConnection connection = url.openConnection();
            inputStream = new BufferedInputStream(connection.getInputStream());
            inputStream.mark(Integer.MAX_VALUE);

            contentType = connection.getContentType();
        }
        if (contentType == null) {
            contentType = tika.detect(inputStream, fileName);
            inputStream.reset();
        }
        if (file2 != null) {
            fileName2 = file2.getOriginalFilename();
            inputStream2 = new BufferedInputStream(file2.getInputStream());
            inputStream2.mark(Integer.MAX_VALUE); // allow reset
            contentType2 = file2.getContentType();
        }
        if (file2 != null && contentType2 == null) {
            contentType2 = tika.detect(inputStream2, fileName2);
            inputStream2.reset();
        }
        sha256Hash = DigestUtils.sha256Hex(inputStream);
        if (file2 != null) {
            sha256Hash2 = DigestUtils.sha256Hex(inputStream2);
            inputStream2.reset();
        }
        inputStream.reset();
        if (file2 != null) {
            inputStream2.reset();
        }

        log.info("Received file: {}, hash={}", fileName, sha256Hash);
        if (file2 != null) {
            log.info("Received file2: {}, hash={}", fileName2, sha256Hash2);
        }

        // --- Extract EXIF + Metadata ---
        Map<String, Map<String, String>> extracted = extract(inputStream, contentType, fileName);

        List<Map<String, Map<String, String>>> extractedList = new ArrayList<>();
        extractedList.add(extracted);
        if (file2 != null) {
            Map<String, Map<String, String>> extracted2 = extract(inputStream2, contentType2, fileName2);
            extractedList.add(extracted2);
        }
        String extractedJson = gson.toJson(extractedList);

        // 3. Prompt for Gemini
        String prompt = """
                  You are a forensic media analysis expert and pledge proof verification expert.

                  Task:
                  Analyze this media file and extract detailed EXIF and metadata information. For each key in the EXIF/metadata, provide the value if available. If a value is missing, return null. Additionally, verify if the media content fulfills the pledge requirements (quantity and units), perform proof verification for carbon accounting eligibility, and provide an AI analysis score including approval status, confidence score, and explanatory notes.

                  Additionally, detect any signs of tampering or manipulation and provide a quantitative confidence score:
                  - "tampering_detected": true/false
                  - "tampering_score": integer 0-100 (0 = no signs of tampering, 100 = highly likely tampered)
                  - "tampering_notes": textual explanation of what indicators were found or why the score is low

                  Return the following JSON structure ONLY:

                  {
                  "mediaFileAnalysis":[
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
                    "description": "Brief human-readable description of the media content.",
                    "detail":{
                      "height": "...",
                      "weight": "...",
                      "age": "...",
                      "type": "..."
                    },
                    "verify":{
                    "isFileAccountForCarbonAccounting": true/false,
                    "calculateCarbonFootPrint":{
                      "carbon_footprint_number_kg_co2e": number,
                      "carbonFootPrintNotes": "..."
                    },
                    "sdgItFallsIn":[
                       {
                         "SDG no.": number,
                         "SDG name": "...",
                         "contribution_percentage": number,
                         "notes": "..."
                        }
                    ],
                    },
                    "aiAnalysis": {
                      "approved": true/false,
                      "isAiGenerated" true/false,
                      "aiGeneratedNotes": "...",
                      "approved_score": 0-100,
                      "analysis_notes": "Brief explanation why approved or not"
                    }
                  }],
                  "pledgeVerification":{
                   "overallAiAnalysis": {
                      "approved": true/false,
                      "isAiGenerated" true/false,
                      "aiGeneratedNotes": "...",
                      "approved_score": 0-100,
                      "analysis_notes": "Brief explanation why approved or not"
                    },
                    "overallVerify":{
                    "isFilesAccountForCarbonAccounting": true/false,
                    "calculateCarbonFootPrint":{
                      "total_carbon_footprint_number_kg_co2e": number,
                      "carbonFootPrintNotes": "..."
                    },
                  }
                  }}

                  Pledge Verification Context:
                  - User Input Prompt: %s
                  - Expected Quantity: %d
                  - Units: %s
                  
                  Instructions:
                  - Focus first on retrieving **EXIF details** from all available media types (images, video, PDFs, etc.).
                  - Use any detectable clues for tampering, including metadata inconsistencies, cloned regions, compression artifacts, altered timestamps, or software fingerprints, dcterms:modified and dcterms:created.
                  - Provide a confidence score for tampering as 0-100.
                  - include 1 more key called detail and add height, weight, age, type of main element, if not sure then add assumption but mention is assumed.
                  - include 1 more key called verify and check if the file account for carbon foot print calculations, and if yes calculate carbon foot print for that means find main element and find its carbon foot print, give detail like giving now but also key a number field direct number we get, and add sdg it falls under an percentage contribution for each sdg.
                  - If some EXIF or metadata or any field is missing, use null or empty fields.
                                                                    
                  Instructions for AI Analysis:
                  - First extract EXIF/metadata and check for tampering as usual.
                  - Then verify if the media content fulfills the pledge:
                    - If quantity = 0 or missing, verify based on the input prompt and the main element detected in the media.
                    - If quantity is provided, the media must show at least that quantity of the pledged element.
                    - Approval = true only if the pledged quantity (and unit) is fully satisfied or exceeded.
                    - If detected quantity < pledged quantity, approval = false.
                    - If units are missing, assume "pieces". If units are specified (kg, liters, etc.), verify according to that unit.
                  - Set "aiAnalysis.approved" = true only if pledge is fulfilled. Set "approved_score" proportionally if partially fulfilled. Add explanation in "approved_notes".
                  - Include specific details from the media (number of items detected, type of items) in "approved_notes" and detail about you believe.
                  - for valid pledge verification is should full fill pledge fully not partially, if quantity and unit is there,else verify based on content described in inputPrompt.
                  - Only if the pledge is valid and file can be used for carbon accounting, set "verify.isFileAccountForCarbonAccounting" = true and calculate carbon footprint and SDG contributions.
                  - If quantity is 0 or missing, attempt to verify based on content described in inputPrompt.
                  - Add AI-generated detection:
                     - Detect if the file or content is ai generated or not.
                     - Include "isAiGenerated" = true/false and "aiGeneratedNotes".
                     - If "isAiGenerated" = true, then "approved" must be false regardless of quantity.
                  
                  Date Comparison Rules:
                  - All EXIF, dcterms:created, and dcterms:modified dates must be compared to the reference Current Date Time in UTC.
                  - Treat EXIF timestamps as local device time; convert to UTC if needed.
                  - Do NOT mark a timestamp as "future" unless it is strictly later than the reference UTC date/time by more than 1 hour.
                  - Ignore minor discrepancies due to time zones or device clock offsets.
                  - If a timestamp appears to be in the future due to format misinterpretation or model error, mark it as valid and set "tampering_detected": false.
                  
                  Multiple Media File Handling:
                  - Each submitted media file (image, video, PDF) should be analyzed individually.
                  - Include in "mediaFileAnalysis" an entry for each file with all keys: exif, metadata, tampering, detail, verify, aiAnalysis, description.
                  - Detect duplicates using hash/fingerprinting or content similarity; only count unique media toward pledge fulfillment.
                  - For AI-generated content, mark "isAiGenerated": true and "aiGeneratedNotes", and exclude it from pledge fulfillment.
                  - If multiple files show the same main element from different angles, treat as single unique contribution.
                  - Aggregate all individual analyses to determine "overallAiAnalysis" and "overallVerify" for the total submission:
                      - "approved" = true only if total unique media fulfills the pledge quantity and unit.
                      - "isFilesAccountForCarbonAccounting" = true only if enough unique media files satisfy pledge requirements for carbon accounting.
                      - Provide notes explaining which files were duplicates, AI-generated, or contributed to the overall approval.
                  - Ensure that for pledge verification, total unique quantity = pledged quantity or more. Approval = false if insufficient.
                  - overallVerify: calculateCarbonFootPrint include only approved files aiAnalysis: approved = true.
                  
                  Return **valid JSON only**, do not include explanatory text outside the JSON.
                  Return JSON only with keys: exif, geolocation, metadata, tampering, description, aiAnalysis, detail, verify
                  Include all metadata and exif from local extraction also in response.
                  Known Metadata (from local extraction):
                  %s

                 Current Date Time in UTC: %s
                 (Important: Treat this as reference only. When comparing metadata dates, ensure correct YYYY:MM:DD or ISO formats.
                 Do NOT mark dates as "future" tampering if they are earlier than or equal to the current UTC reference.
                 Only flag as tampering if a metadata date is truly later than the reference AND other inconsistencies exist.
                 If the date format is ambiguous, assume it's a normal timestamp, not manipulation.)
                                                                                                                                                                      
                """.formatted(inputPrompt, quantity, units, extractedJson, new Date());

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
            parts.add(Part.fromBytes(file.getBytes(), contentType));
        } else {
            parts.add(Part.fromUri(publicUrl, contentType));
        }
        if (file2 != null) {
            parts.add(Part.fromBytes(file2.getBytes(), contentType2));
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
//        if (file2 != null) {
//            response.put("fileName2", fileName2);
//            response.put("hash2", sha256Hash2);
//            response.put("local_extraction2", extracted2);
//        }
//        response.put("fileName", fileName);
//        response.put("hash", sha256Hash);
//        response.put("local_extraction", extractedList);
        response.put("analysis", gson.fromJson(parsed, Map.class));

        log.info("Analysis completed : {}", response);

        return ResponseEntity.ok(response);
    }
}
