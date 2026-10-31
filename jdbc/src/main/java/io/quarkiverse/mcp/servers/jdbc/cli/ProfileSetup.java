package io.quarkiverse.mcp.servers.jdbc.cli;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import io.quarkiverse.mcp.servers.jdbc.database.DbType;
import io.quarkiverse.mcp.servers.jdbc.database.JdbcUrlGuard;
import io.quarkiverse.mcp.servers.jdbc.policy.PermissionPolicy;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyLoader;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyMetadataCheck;
import io.quarkiverse.mcp.servers.jdbc.policy.PolicyValidator;
import io.quarkiverse.mcp.servers.jdbc.profile.DbProfile;
import io.quarkiverse.mcp.servers.jdbc.profile.LabelRules;
import io.quarkiverse.mcp.servers.jdbc.profile.ProfileValidator;
import io.quarkiverse.mcp.servers.jdbc.secret.FilePerms;

/** Trusted admin input: one connection line followed by explicit policy settings. Never executes pasted SQL. */
final class ProfileSetup {
    static final class Settings {
        boolean tls = true;
        boolean override;
        int maxRows = 500;
        boolean update;
        final List<String[]> tables = new ArrayList<>();
        final List<io.quarkiverse.mcp.servers.jdbc.change.SqlUpdateTemplate> templates = new ArrayList<>();
    }

    static Settings parse(List<String> lines) {
        Settings settings = new Settings();
        Set<String> seen = new LinkedHashSet<>();
        Set<String> tableNames = new LinkedHashSet<>();
        Set<String> templateNames = new LinkedHashSet<>();
        for (String line : lines) {
            int equals = line.indexOf('=');
            if (equals < 1) {
                throw new IllegalArgumentException("設定須使用 KEY=VALUE；資料表請用 UPDATE=SCHEMA.TABLE,SCHEMA.TABLE");
            }
            String key = line.substring(0, equals).strip().toUpperCase(Locale.ROOT);
            String value = line.substring(equals + 1).strip();
            if (!Set.of("TLS", "ACCESS", "MAX_ROWS", "OVERRIDE", "UPDATE", "SQL").contains(key)) {
                throw new IllegalArgumentException("不支援的設定欄位；只接受 TLS、ACCESS、MAX_ROWS、OVERRIDE、UPDATE、SQL");
            }
            if (!seen.add(key) && !key.equals("UPDATE") && !key.equals("SQL")) {
                throw new IllegalArgumentException("設定欄位不可重複");
            }
            switch (key) {
                case "TLS" -> {
                    if (!value.equalsIgnoreCase("ON") && !value.equalsIgnoreCase("OFF")) {
                        throw new IllegalArgumentException("TLS 必須是 ON 或 OFF");
                    }
                    settings.tls = value.equalsIgnoreCase("ON");
                }
                case "OVERRIDE" -> {
                    if (!value.equalsIgnoreCase("YES") && !value.equalsIgnoreCase("NO")) {
                        throw new IllegalArgumentException("OVERRIDE 必須是 YES 或 NO");
                    }
                    settings.override = value.equalsIgnoreCase("YES");
                }
                case "MAX_ROWS" -> {
                    if (!value.matches("[0-9]{1,3}")) {
                        throw new IllegalArgumentException("MAX_ROWS 必須介於 1–500");
                    }
                    settings.maxRows = Integer.parseInt(value);
                    if (settings.maxRows < 1 || settings.maxRows > 500) {
                        throw new IllegalArgumentException("MAX_ROWS 必須介於 1–500");
                    }
                }
                case "ACCESS" -> {
                    if (!value.equalsIgnoreCase("READ_ONLY") && !value.equalsIgnoreCase("UPDATE")) {
                        throw new IllegalArgumentException("ACCESS 必須是 READ_ONLY 或 UPDATE");
                    }
                    settings.update = value.equalsIgnoreCase("UPDATE");
                }
                case "UPDATE" -> {
                    for (String table : value.split(",", -1)) {
                        String[] parts = table.strip().split("\\.", -1);
                        if (parts.length != 2 || !identifier(parts[0]) || !identifier(parts[1])) {
                            throw new IllegalArgumentException("UPDATE 只接受 SCHEMA.TABLE 清單，不接受 SQL、萬用字元或引號");
                        }
                        if (!tableNames.add(table.strip().toUpperCase(Locale.ROOT))) {
                            throw new IllegalArgumentException("UPDATE 資料表不可重複");
                        }
                        settings.tables.add(parts);
                    }
                }
                case "SQL" -> {
                    int separator = value.indexOf("##");
                    if (separator < 1) {
                        throw new IllegalArgumentException("SQL 格式：SQL=範本名稱##UPDATE SCHEMA.TABLE SET COL=? WHERE KEY=?");
                    }
                    var template = new io.quarkiverse.mcp.servers.jdbc.change.SqlUpdateTemplate(
                            value.substring(0, separator).strip(), value.substring(separator + 2).strip());
                    if (!templateNames.add(template.id().toUpperCase(Locale.ROOT))) {
                        throw new IllegalArgumentException("SQL 範本名稱不可重複");
                    }
                    settings.templates.add(template);
                }
                default -> throw new IllegalStateException();
            }
        }
        if (settings.update != (!settings.tables.isEmpty() || !settings.templates.isEmpty())) {
            throw new IllegalArgumentException("ACCESS=UPDATE 時必須有 UPDATE 或 SQL 清單；READ_ONLY 不可有寫入規則");
        }
        return settings;
    }

    private static boolean identifier(String name) {
        return name.matches("[A-Za-z_][A-Za-z0-9_$#]{0,127}");
    }

    static void prompt(GatewayContext ctx, BufferedReader in, boolean stdin, boolean skipTest) throws Exception {
        System.err.println("【READ sample】");
        System.err.println("MY-DEV##DB2_LUW##jdbc:db2://db.example:60000/TESTDB##dbuser##APP##密碼");
        System.err.println("TLS=OFF\nACCESS=READ_ONLY\nMAX_ROWS=500\nOVERRIDE=YES\nEND");
        System.err.println("【UPDATE＋TABLE＋SQL sample】");
        System.err.println("MY-DEV##DB2_LUW##jdbc:db2://db.example:60000/TESTDB##dbuser##APP##密碼");
        System.err.println("TLS=OFF\nACCESS=UPDATE\nMAX_ROWS=500\nOVERRIDE=YES\nUPDATE=APP.CUSTOMERS,APP.PAYMENTS");
        System.err.println("SQL=order_status##UPDATE APP.ORDERS SET STATUS=? WHERE ORDER_ID=?\nEND");
        System.err.println("選一組修改後貼上，END 結束；內容隱藏。TABLE 需確認，SQL 範本免逐次審核。");
        char[] first = PasswordPrompt.password("貼上設定，第一行為連線", stdin, in);
        try (PastedProfile pasted = PastedProfile.parse(first)) {
            Arrays.fill(first, '\0');
            List<String> lines = new ArrayList<>();
            while (true) {
                char[] next = PasswordPrompt.password("", stdin, in);
                String line;
                try {
                    line = new String(next).strip();
                } finally {
                    Arrays.fill(next, '\0');
                }
                if (line.equals("END")) {
                    break;
                }
                if (lines.size() >= 100) {
                    throw new IllegalArgumentException("設定行數最多 100 行");
                }
                lines.add(line);
            }
            Settings settings = parse(lines);
            char[] password = pasted.password != null ? pasted.password : PasswordPrompt.password("Password", stdin, in);
            try {
                apply(ctx, pasted.fields, password, settings, skipTest);
            } finally {
                Arrays.fill(password, '\0');
            }
        } finally {
            Arrays.fill(first, '\0');
        }
    }

    static DbProfile apply(GatewayContext ctx, String[] fields, char[] password, Settings settings, boolean skipTest)
            throws Exception {
        String label = LabelRules.normalize(fields[0]);
        DbProfile old = ctx.registry.byLabel(label).orElse(null);
        if (old != null && !settings.override) {
            throw new IllegalArgumentException("同名 DB 已存在；若要整組覆蓋，請設定 OVERRIDE=YES");
        }
        DbProfile candidate = new DbProfile(old == null ? UUID.randomUUID().toString() : old.profileId(), label,
                DbType.parse(fields[1]), fields[2], fields[3], password, fields[4].isEmpty() ? null : fields[4],
                old == null || old.enabled());
        new ProfileValidator(new JdbcUrlGuard(Set.of(), settings.tls)).validate(candidate);
        if (!settings.tls) {
            System.err.println("提醒：本組設定 TLS=OFF，允許無 TLS 的測試 DB 連線。");
        }
        FilePerms.ensureSecureDir(ctx.paths.permissionsDir());
        Path target = LabelRules.policyPath(ctx.paths.permissionsDir(), label);
        if (old == null && Files.exists(target)) {
            throw new IllegalArgumentException("存在同名遺留權限檔，請先移走，不會直接覆蓋");
        }
        if (Files.isSymbolicLink(target)) {
            throw new IllegalArgumentException("權限檔不可是 symbolic link");
        }
        byte[] original = Files.exists(target) ? Files.readAllBytes(target) : null;
        Path temporary = Files.createTempFile(ctx.paths.permissionsDir(), "setup-", ".yaml");
        try {
            FilePerms.restrictFile(temporary);
            Files.writeString(temporary, policyYaml(candidate, settings), StandardCharsets.UTF_8);
            PermissionPolicy policy = PolicyValidator.validate(PolicyLoader.load(temporary), label, candidate.profileId());
            if (!skipTest) {
                ctx.connections.test(candidate);
                if (settings.update
                        && !PolicyMetadataCheck.check(policy, candidate.withEnabled(true), ctx.connections).isEmpty()) {
                    throw new IllegalArgumentException("UPDATE 白名單的資料表驗證失敗；未儲存設定");
                }
            }
            List<DbProfile> previous = ctx.registry.all();
            List<DbProfile> next = new ArrayList<>(previous);
            next.removeIf(p -> p.profileId().equals(candidate.profileId()));
            next.add(candidate);
            ctx.store.write(next);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                ctx.policies.activate(candidate);
            } catch (Exception failed) {
                ctx.store.write(previous);
                if (original == null) {
                    Files.deleteIfExists(target);
                } else {
                    Path rollback = Files.createTempFile(ctx.paths.permissionsDir(), "rollback-", ".yaml");
                    try {
                        FilePerms.restrictFile(rollback);
                        Files.write(rollback, original);
                        Files.move(rollback, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                    } finally {
                        Files.deleteIfExists(rollback);
                    }
                }
                throw failed;
            }
            ctx.registry.replaceAll(next);
            ctx.connections.invalidate(candidate.profileId());
            System.err.println((old == null ? "已建立 " : "已覆蓋 ") + label + "；權限 " + policy.access()
                    + " 已生效；每次查詢最多 " + settings.maxRows + " 筆。");
            System.err.println("權限檔：" + target);
            return candidate;
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static String policyYaml(DbProfile profile, Settings settings) throws Exception {
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("version", 1);
        policy.put("profile", profile.label());
        policy.put("profileId", profile.profileId());
        policy.put("access", settings.update ? "READ_WRITE_WHITELIST" : "READ_ONLY");
        policy.put("read", Map.of("maxRows", settings.maxRows, "timeoutSeconds", 30));
        if (settings.update) {
            List<Map<String, Object>> whitelist = new ArrayList<>();
            for (String[] table : settings.tables) {
                whitelist.add(Map.of("schema", table[0], "table", table[1], "operations", List.of("UPDATE")));
            }
            var templates = settings.templates.stream()
                    .map(t -> Map.of("id", t.id(), "sql", t.sql(), "autoExecute", true)).toList();
            policy.put("write", Map.of("maxAffectedRows", 100, "requireConfirmation", true, "whitelist", whitelist,
                    "templates", templates));
        }
        return new ObjectMapper(new YAMLFactory()).writeValueAsString(policy);
    }
}
