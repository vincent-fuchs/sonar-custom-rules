package org.sonar.samples.java.checks;

import org.junit.Test;
import org.sonar.java.checks.verifier.JavaCheckVerifier;
import org.sonar.java.testing.CheckVerifier;

public class LogExceptionsCorrectlyCheckTest {

    @Test
    public void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/LogExceptionsCheck.java")
                .withCheck( new LogExceptionsCorrectlyCheck())
                .verifyIssues();
    }
}
