package io.quarkiverse.mcp.servers.jdbc.cli;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

import io.quarkiverse.mcp.servers.jdbc.database.DriverLoader;
import io.quarkiverse.mcp.servers.jdbc.profile.Settings;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Parameters;

@Command(name = "driver", description = "Trust external JDBC driver jars (for example IBM JCC)", subcommands = {
        DriverCommand.Pin.class, DriverCommand.ListCmd.class, DriverCommand.Unpin.class })
public class DriverCommand implements Runnable {

    @Override
    public void run() {
        new picocli.CommandLine(this).usage(System.err);
    }

    @Command(name = "pin", description = "Record the SHA-256 of a jar in <config-dir>/drivers/ so it may be loaded")
    static class Pin implements Callable<Integer> {
        @Mixin
        CommonOptions common;

        @Parameters(index = "0", paramLabel = "JAR_NAME", description = "File name inside the drivers directory, e.g. db2jcc4.jar")
        String jarName;

        @Override
        public Integer call() throws Exception {
            var paths = common.paths();
            Path jar = paths.driversDir().resolve(jarName).normalize();
            if (!jar.getParent().equals(paths.driversDir().normalize()) || !Files.isRegularFile(jar)) {
                System.err.println("No such file in " + paths.driversDir() + ": " + jarName);
                return 1;
            }
            String sha = DriverLoader.sha256Of(jar);
            new Settings(paths.settingsFile()).pinDriver(jarName, sha);
            System.out.println("Pinned " + jarName);
            System.out.println("SHA-256 " + sha);
            System.out.println("Compare this with the checksum published by the vendor before relying on it.");
            return 0;
        }
    }

    @Command(name = "list", description = "Show pinned drivers")
    static class ListCmd implements Callable<Integer> {
        @Mixin
        CommonOptions common;

        @Override
        public Integer call() {
            var pins = new Settings(common.paths().settingsFile()).pinnedDrivers();
            if (pins.isEmpty()) {
                System.out.println("No drivers are pinned.");
            }
            pins.forEach((k, v) -> System.out.println(k + "  " + v));
            return 0;
        }
    }

    @Command(name = "unpin", description = "Stop trusting a driver jar")
    static class Unpin implements Callable<Integer> {
        @Mixin
        CommonOptions common;

        @Parameters(index = "0", paramLabel = "JAR_NAME")
        String jarName;

        @Override
        public Integer call() throws Exception {
            new Settings(common.paths().settingsFile()).unpinDriver(jarName);
            return 0;
        }
    }
}
