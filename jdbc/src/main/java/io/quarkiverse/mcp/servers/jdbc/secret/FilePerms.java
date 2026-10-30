package io.quarkiverse.mcp.servers.jdbc.secret;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Set;

/**
 * Creates and checks owner-only files and directories: POSIX 0700 / 0600, or an owner-only ACL on Windows.
 */
public final class FilePerms {

    private static final Set<PosixFilePermission> DIR = PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> FILE = PosixFilePermissions.fromString("rw-------");

    private FilePerms() {
    }

    private static boolean posix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    /** Creates the directory (and parents) with owner-only access if needed, then verifies it. */
    public static void ensureSecureDir(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            Path parent = dir.toAbsolutePath().getParent();
            if (parent != null && !Files.exists(parent)) {
                ensureSecureDir(parent);
            }
            if (posix()) {
                Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(DIR));
            } else {
                Files.createDirectory(dir);
                restrictToOwner(dir);
            }
        }
        verifyDir(dir);
    }

    public static void restrictFile(Path file) throws IOException {
        if (posix()) {
            Files.setPosixFilePermissions(file, FILE);
        } else {
            restrictToOwner(file);
        }
    }

    public static void verifyDir(Path dir) throws IOException {
        if (Files.isSymbolicLink(dir) || !Files.isDirectory(dir)) {
            throw new InsecurePermissionsException("Not a regular directory: " + dir.getFileName());
        }
        if (posix()) {
            Set<PosixFilePermission> actual = Files.getPosixFilePermissions(dir);
            if (actual.stream().anyMatch(p -> !DIR.contains(p))) {
                throw new InsecurePermissionsException("Directory " + dir + " must be accessible by its owner only (0700)");
            }
        }
    }

    public static void verifyFile(Path file) throws IOException {
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file)) {
            throw new InsecurePermissionsException("Not a regular file: " + file.getFileName());
        }
        if (posix()) {
            Set<PosixFilePermission> actual = Files.getPosixFilePermissions(file);
            if (actual.stream().anyMatch(p -> !FILE.contains(p))) {
                throw new InsecurePermissionsException(
                        "File " + file.getFileName() + " must be readable by its owner only (0600)");
            }
        }
    }

    private static void restrictToOwner(Path path) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
        if (view == null) {
            throw new InsecurePermissionsException("Cannot restrict permissions on this file system");
        }
        UserPrincipal owner = Files.getOwner(path);
        AclEntry entry = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner)
                .setPermissions(Set.of(AclEntryPermission.values())).build();
        view.setAcl(List.of(entry));
    }

    public static final class InsecurePermissionsException extends IOException {
        public InsecurePermissionsException(String message) {
            super(message);
        }
    }
}
