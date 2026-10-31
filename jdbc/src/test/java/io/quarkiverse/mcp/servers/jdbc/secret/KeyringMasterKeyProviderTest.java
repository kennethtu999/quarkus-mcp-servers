package io.quarkiverse.mcp.servers.jdbc.secret;

import static org.assertj.core.api.Assertions.*;

import java.nio.file.Path;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.javakeyring.BackendNotSupportedException;
import com.github.javakeyring.PasswordAccessException;

import io.quarkiverse.mcp.servers.jdbc.secret.MasterKeyProvider.KeyUnavailableException;
import io.quarkiverse.mcp.servers.jdbc.secret.MasterKeyProvider.KeyUnavailableException.Reason;

class KeyringMasterKeyProviderTest {
    @TempDir
    Path tmp;

    static class Fake implements KeyringMasterKeyProvider.Access {
        String value;
        Exception readFailure;
        Exception writeFailure;
        int writes;
        boolean discardWrite;

        public String read(String service, String account) throws Exception {
            if (readFailure != null)
                throw readFailure;
            return value;
        }

        public void write(String service, String account, String value) throws Exception {
            writes++;
            if (writeFailure != null)
                throw writeFailure;
            if (!discardWrite)
                this.value = value;
        }

        public void close() {
        }
    }

    KeyringMasterKeyProvider provider(Fake fake) {
        return new KeyringMasterKeyProvider(tmp, "kid", () -> fake);
    }

    @Test
    void nullOnFirstInitCreatesAndVerifiesOneKey() throws Exception {
        Fake fake = new Fake();
        var provider = provider(fake);
        byte[] key = provider.loadOrCreate();
        assertThat(key).hasSize(32).isEqualTo(provider.load()).isEqualTo(provider.loadOrCreate());
        assertThat(fake.writes).isEqualTo(1);
    }

    @Test
    void loadMissingNeverWrites() {
        Fake fake = new Fake();
        assertThatThrownBy(provider(fake)::load).isInstanceOfSatisfying(KeyUnavailableException.class,
                failure -> assertThat(failure.reason()).isEqualTo(Reason.NOT_FOUND));
        assertThat(fake.writes).isZero();
    }

    @Test
    void nativeMissingCredentialCreatesKey() throws Exception {
        Fake fake = new Fake() {
            public String read(String service, String account) throws Exception {
                if (value == null)
                    throw new PasswordAccessException("No stored credentials match " + service + " account: " + account);
                return value;
            }
        };
        assertThat(provider(fake).loadOrCreate()).hasSize(32);
        assertThat(fake.writes).isEqualTo(1);
    }

    @Test
    void deniedAndUnknownPasswordErrorsNeverCreateOrLeakMessages() {
        for (Exception cause : new Exception[] { new PasswordAccessException("denied SECRET-SENTINEL"),
                new NullPointerException("SECRET-SENTINEL"), new SecurityException("SECRET-SENTINEL") }) {
            Fake fake = new Fake();
            fake.readFailure = cause;
            assertThatThrownBy(provider(fake)::loadOrCreate).isInstanceOfSatisfying(KeyUnavailableException.class,
                    failure -> {
                        assertThat(failure.reason()).isEqualTo(Reason.ACCESS_FAILED);
                        assertThat(failure.getCause()).isSameAs(cause);
                        assertThat(failure.getMessage()).contains("read").doesNotContain("SECRET-SENTINEL");
                    });
            assertThat(fake.writes).isZero();
        }
    }

    @Test
    void corruptExistingKeyNeverGetsReplaced() {
        for (String value : new String[] { "", "broken-base64!", Base64.getEncoder().encodeToString(new byte[16]) }) {
            Fake fake = new Fake();
            fake.value = value;
            assertThatThrownBy(provider(fake)::loadOrCreate).isInstanceOfSatisfying(KeyUnavailableException.class,
                    failure -> assertThat(failure.reason()).isEqualTo(Reason.INVALID_KEY));
            assertThat(fake.writes).isZero();
        }
    }

    @Test
    void writeFailureRetainsCauseAndCannotReturnUnpersistedKey() {
        Fake fake = new Fake();
        fake.writeFailure = new PasswordAccessException("secret");
        assertThatThrownBy(provider(fake)::loadOrCreate).hasCause(fake.writeFailure).hasMessageContaining("write");
    }

    @Test
    void successfulWriteMustReadBackSameKey() {
        Fake fake = new Fake();
        fake.discardWrite = true;
        assertThatThrownBy(provider(fake)::loadOrCreate).hasMessageContaining("after write");
    }

    @Test
    void backendUnavailablePreservesInitializationCause() {
        Throwable original = new NullPointerException("secret");
        var provider = new KeyringMasterKeyProvider(tmp, "kid", () -> {
            throw new BackendNotSupportedException("native secret", original);
        });
        assertThatThrownBy(provider::loadOrCreate).isInstanceOfSatisfying(KeyUnavailableException.class, failure -> {
            assertThat(failure.reason()).isEqualTo(Reason.BACKEND_UNAVAILABLE);
            assertThat(failure.getCause().getCause()).isSameAs(original);
            assertThat(failure.getMessage()).doesNotContain("secret");
        });
    }

    @Test
    void onlyExactKnownMissingResultsAreAccepted() {
        assertThat(KeyringMasterKeyProvider.isMissing(new PasswordAccessException("Error code 1168"), "a")).isTrue();
        assertThat(KeyringMasterKeyProvider.isMissing(new PasswordAccessException("Error code 5"), "a")).isFalse();
        assertThat(KeyringMasterKeyProvider.isMissing(new PasswordAccessException("Password not Found"), "a")).isTrue();
        assertThat(KeyringMasterKeyProvider.isMissing(new PasswordAccessException("Password is not in wallet"), "a")).isTrue();
        assertThat(KeyringMasterKeyProvider.isMissing(new PasswordAccessException("Other error: Password not Found"), "a"))
                .isFalse();
    }

    static NullPointerException unavailableCollection() {
        var failure = new NullPointerException("SECRET-SENTINEL");
        failure.setStackTrace(new StackTraceElement[] {
                new StackTraceElement("com.github.javakeyring.internal.freedesktop.SimpleCollection", "createItem",
                        "SimpleCollection.java", 314) });
        return failure;
    }

    @Test
    void missingCollectionOnFirstWriteIsUnavailableButOtherWriteErrorsRemainFailures() {
        for (Exception cause : new Exception[] { unavailableCollection(), new NullPointerException("unknown"),
                new PasswordAccessException("denied"), new SecurityException("denied") }) {
            Fake fake = new Fake();
            fake.writeFailure = cause;
            assertThatThrownBy(provider(fake)::loadOrCreate).isInstanceOfSatisfying(KeyUnavailableException.class, failure -> {
                assertThat(failure.reason()).isEqualTo(cause == fake.writeFailure
                        && cause.getStackTrace()[0].getClassName().endsWith("SimpleCollection")
                                ? Reason.BACKEND_UNAVAILABLE
                                : Reason.ACCESS_FAILED);
                assertThat(failure.getCause()).isSameAs(cause);
                assertThat(failure.getMessage()).doesNotContain("SECRET-SENTINEL");
            });
        }
    }

    @Test
    void rotationAndExistingKeyReadsNeverClassifyCollectionNpeAsFirstCreation() {
        Fake fake = new Fake();
        fake.writeFailure = unavailableCollection();
        assertThatThrownBy(() -> provider(fake).store(new byte[32])).isInstanceOfSatisfying(KeyUnavailableException.class,
                failure -> assertThat(failure.reason()).isEqualTo(Reason.ACCESS_FAILED));
        fake.readFailure = unavailableCollection();
        assertThatThrownBy(provider(fake)::loadOrCreate).isInstanceOfSatisfying(KeyUnavailableException.class,
                failure -> assertThat(failure.reason()).isEqualTo(Reason.ACCESS_FAILED));
    }
}
