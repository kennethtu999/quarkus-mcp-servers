package io.quarkiverse.mcp.servers.jdbc.policy;

import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.yaml.snakeyaml.LoaderOptions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * Reads a policy file into a plain {@link JsonNode} tree, refusing everything that is not a small, plain YAML document.
 * <p>
 * Jackson's YAML module does <em>not</em> reject anchors, aliases, merge keys, explicit tags or deep nesting even when
 * SnakeYAML's {@link LoaderOptions} ask for it, so those are rejected here by scanning the raw text before parsing.
 * Policy files are tiny and hand written, so refusing these constructs costs nothing and removes whole classes of
 * surprise (an alias can make a file mean something different from what it visibly says).
 */
public final class PolicyLoader {

    public static final int MAX_BYTES = 64 * 1024;
    static final int MAX_DEPTH = 8;

    private static final ObjectMapper YAML;

    static {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(0);
        options.setAllowRecursiveKeys(false);
        options.setCodePointLimit(MAX_BYTES);
        YAML = new ObjectMapper(YAMLFactory.builder().loaderOptions(options).build())
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }

    private PolicyLoader() {
    }

    public record Loaded(JsonNode tree, String hash) {
    }

    public static Loaded load(Path file) throws PolicyException {
        byte[] bytes;
        try {
            if (Files.isSymbolicLink(file) || !Files.isRegularFile(file)) {
                throw new PolicyException("Policy file is missing or not a regular file");
            }
            long size = Files.size(file);
            if (size > MAX_BYTES) {
                throw new PolicyException("Policy file is larger than " + MAX_BYTES + " bytes");
            }
            bytes = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new PolicyException("Policy file cannot be read");
        }
        return parse(bytes);
    }

    public static Loaded parse(byte[] bytes) throws PolicyException {
        if (bytes.length > MAX_BYTES) {
            throw new PolicyException("Policy file is larger than " + MAX_BYTES + " bytes");
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new PolicyException("Policy file is not valid UTF-8");
        }
        rejectUnsafeConstructs(text);
        try {
            JsonNode tree = YAML.readTree(text);
            if (tree == null || !tree.isObject()) {
                throw new PolicyException("Policy file must be a YAML mapping");
            }
            if (depth(tree) > MAX_DEPTH) {
                throw new PolicyException("Policy file is nested too deeply");
            }
            return new Loaded(tree, "sha256:" + sha256(bytes));
        } catch (JsonProcessingException e) {
            // Do not echo parser messages: they can quote file content.
            throw new PolicyException("Policy file is not valid YAML (line " + line(e) + ")");
        }
    }

    /** Line-oriented scan that ignores anything inside comments and quoted scalars. */
    static void rejectUnsafeConstructs(String text) throws PolicyException {
        int lineNo = 0;
        for (String line : text.split("\r\n|\r|\n", -1)) {
            lineNo++;
            if (lineNo == 1 && line.startsWith("﻿")) {
                line = line.substring(1);
            }
            String trimmed = line.strip();
            if (trimmed.equals("---") || trimmed.startsWith("--- ") || trimmed.equals("...") || trimmed.startsWith("%")) {
                if (!(lineNo == 1 && trimmed.equals("---"))) {
                    throw new PolicyException("Multiple documents and directives are not allowed (line " + lineNo + ")");
                }
            }
            char quote = 0;
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                if (quote != 0) {
                    if (c == quote) {
                        quote = 0;
                    } else if (c == '\\' && quote == '"') {
                        i++;
                    }
                    continue;
                }
                if (c == '"' || c == '\'') {
                    if (i == 0 || " \t[{,:-".indexOf(line.charAt(i - 1)) >= 0) {
                        quote = c;
                    }
                    continue;
                }
                if (c == '#' && (i == 0 || Character.isWhitespace(line.charAt(i - 1)))) {
                    break;
                }
                boolean tokenStart = i == 0 || " \t[{,:-".indexOf(line.charAt(i - 1)) >= 0;
                if (tokenStart && (c == '&' || c == '*')) {
                    throw new PolicyException("YAML anchors and aliases are not allowed (line " + lineNo + ")");
                }
                if (tokenStart && c == '!') {
                    throw new PolicyException("YAML tags are not allowed (line " + lineNo + ")");
                }
                if (c == '<' && line.startsWith("<<", i) && tokenStart) {
                    throw new PolicyException("YAML merge keys are not allowed (line " + lineNo + ")");
                }
            }
        }
    }

    private static int depth(JsonNode n) {
        int max = 0;
        for (JsonNode child : n) {
            max = Math.max(max, depth(child));
        }
        return n.isContainerNode() ? max + 1 : 0;
    }

    private static int line(JsonProcessingException e) {
        return e.getLocation() == null ? 0 : e.getLocation().getLineNr();
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static final class PolicyException extends Exception {
        public PolicyException(String message) {
            super(message);
        }
    }
}
