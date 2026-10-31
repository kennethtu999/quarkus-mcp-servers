package io.quarkiverse.mcp.servers.jdbc.cli;

import java.util.Arrays;

/** Parses five metadata fields and an optional password without copying the complete secret line into a String. */
final class PastedProfile implements AutoCloseable {
    final String[] fields;
    final char[] password;

    private PastedProfile(String[] fields, char[] password) {
        this.fields = fields;
        this.password = password;
    }

    static PastedProfile parse(char[] line) {
        String[] fields = new String[5];
        int start = 0;
        for (int field = 0; field < 5; field++) {
            int end = start;
            while (end + 1 < line.length && !(line[end] == '#' && line[end + 1] == '#')) {
                end++;
            }
            boolean separator = end + 1 < line.length;
            if (!separator) {
                end = line.length;
            }
            if (!separator && field < 4) {
                throw new IllegalArgumentException("單行格式錯誤：需 Label##DB類型##JDBC URL##帳號##Schema，可再加 ##密碼");
            }
            fields[field] = new String(line, start, end - start).strip();
            if (field < 4 && fields[field].isEmpty()) {
                throw new IllegalArgumentException("單行格式錯誤：Label、DB類型、JDBC URL、帳號不可空白");
            }
            start = separator ? end + 2 : line.length;
        }
        // Everything after the fifth delimiter is password, including spaces and further ## sequences.
        return new PastedProfile(fields, start < line.length ? Arrays.copyOfRange(line, start, line.length) : null);
    }

    @Override
    public void close() {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }
}
