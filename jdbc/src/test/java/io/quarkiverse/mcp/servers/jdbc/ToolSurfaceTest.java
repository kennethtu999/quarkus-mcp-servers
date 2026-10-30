package io.quarkiverse.mcp.servers.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import io.quarkiverse.mcp.server.Prompt;
import io.quarkiverse.mcp.server.Tool;

/**
 * Mechanical guard for plan item A20 / DoD "no uncontrolled SQL write tool": the set of MCP tools and prompts
 * compiled into this module must be a subset of the approved list. A merge from upstream that re-introduces
 * {@code read_query}, {@code write_query}, {@code create_table} etc. fails this test.
 */
class ToolSurfaceTest {

    /** Approved public tools (spec section 9). Adding a tool here is a deliberate, reviewed security decision. */
    private static final Set<String> APPROVED_TOOLS = Set.of(
            "db_list_profiles",
            "db_list_tables",
            "db_describe_table",
            "db_query",
            "db_preview_change",
            "db_execute_change");

    @Test
    void onlyApprovedToolsAreRegistered() throws Exception {
        assertThat(scanTools()).isSubsetOf(APPROVED_TOOLS);
    }

    @Test
    void noPromptsAreRegistered() throws Exception {
        assertThat(scanPrompts()).isEmpty();
    }

    @Test
    void scannerSeesTheStubTool() throws Exception {
        // guards against the scan silently finding nothing, which would make the tests above vacuous
        assertThat(scanTools()).contains("db_list_profiles");
    }

    private static Set<String> scanTools() throws Exception {
        Set<String> names = new TreeSet<>();
        for (Class<?> c : mainClasses()) {
            for (var m : c.getDeclaredMethods()) {
                Tool tool = m.getAnnotation(Tool.class);
                if (tool != null) {
                    names.add(tool.name().equals(Tool.ELEMENT_NAME) ? m.getName() : tool.name());
                }
            }
        }
        return names;
    }

    private static Set<String> scanPrompts() throws Exception {
        Set<String> names = new TreeSet<>();
        for (Class<?> c : mainClasses()) {
            for (var m : c.getDeclaredMethods()) {
                if (m.isAnnotationPresent(Prompt.class)) {
                    names.add(m.getName());
                }
            }
        }
        return names;
    }

    private static java.util.List<Class<?>> mainClasses() throws IOException, URISyntaxException, ClassNotFoundException {
        Path root = Path.of(ToolSurfaceTest.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                .resolveSibling("classes");
        java.util.List<Class<?>> result = new java.util.ArrayList<>();
        try (Stream<Path> files = Files.walk(root)) {
            for (Path p : (Iterable<Path>) files.filter(f -> f.toString().endsWith(".class"))::iterator) {
                String name = root.relativize(p).toString().replace('/', '.').replace('\\', '.');
                result.add(Class.forName(name.substring(0, name.length() - ".class".length()), false,
                        ToolSurfaceTest.class.getClassLoader()));
            }
        }
        return result;
    }
}
