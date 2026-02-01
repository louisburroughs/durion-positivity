/*
 * AssertionServices Tests - CAP-275 / ADR-0011
 * 
 * Unit and integration tests for JWT assertion issuance service.
 * These tests verify:
 * - Successful token issuance with valid user context
 * - Error handling for missing configuration
 * - Token structure and claims validation
 * - Configuration service output
 */

import org.moqui.Moqui
import org.moqui.context.ExecutionContext
import spock.lang.*
import io.jsonwebtoken.Jwts
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets

class AssertionServicesTests extends Specification {

    @Shared
    ExecutionContext ec
    
    @Shared
    String testSecret = "test-secret-key-for-unit-tests-minimum-32-chars-long"
    
    @Shared
    String originalSecret
    
    @Shared
    String originalIssuer
    
    @Shared
    String originalAudience

    def setupSpec() {
        // Initialize the framework
        ec = Moqui.getExecutionContext()
        
        // Save original config values
        originalSecret = System.getProperty('moqui.assertion.secret')
        originalIssuer = System.getProperty('moqui.assertion.issuer')
        originalAudience = System.getProperty('moqui.assertion.audience')
        
        // Set test configuration
        System.setProperty('moqui.assertion.secret', testSecret)
        System.setProperty('moqui.assertion.issuer', 'test-moqui')
        System.setProperty('moqui.assertion.audience', 'api-gateway:test')
        System.setProperty('moqui.assertion.ttl', '300')
    }

    def cleanupSpec() {
        // Restore original config
        if (originalSecret) {
            System.setProperty('moqui.assertion.secret', originalSecret)
        } else {
            System.clearProperty('moqui.assertion.secret')
        }
        if (originalIssuer) {
            System.setProperty('moqui.assertion.issuer', originalIssuer)
        } else {
            System.clearProperty('moqui.assertion.issuer')
        }
        if (originalAudience) {
            System.setProperty('moqui.assertion.audience', originalAudience)
        } else {
            System.clearProperty('moqui.assertion.audience')
        }
        
        ec.destroy()
    }

    def setup() {
        // Login as test user for each test
        ec.user.loginUser("john.doe", "moqui")
    }

    def cleanup() {
        ec.user.logoutUser()
    }

    def "issue#JwtAssertion returns valid JWT token"() {
        when:
        def result = ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .call()

        then:
        result != null
        result.token != null
        result.token.split('\\.').length == 3  // JWT has 3 parts
        result.jti != null
        result.jti.length() == 36  // UUID format
        result.expiresAt != null
        result.expiresAt > System.currentTimeMillis() / 1000
    }

    def "issue#JwtAssertion contains correct claims"() {
        when:
        def result = ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .call()

        // Verify the token structure
        byte[] secretBytes = testSecret.getBytes(StandardCharsets.UTF_8)
        SecretKeySpec signingKey = new SecretKeySpec(secretBytes, "HmacSHA256")
        
        def claims = Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(result.token)
            .getPayload()

        then:
        claims.getIssuer() == 'test-moqui'
        claims.getAudience().contains('api-gateway:test')
        claims.getSubject() == 'john.doe'
        claims.getId() == result.jti
        claims.get('roles') != null
        claims.getIssuedAt() != null
        claims.getExpiration() != null
        claims.getExpiration().time > claims.getIssuedAt().time
    }

    def "issue#JwtAssertion includes optional tenantId claim"() {
        when:
        def result = ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .parameters([tenantId: 'TENANT_001'])
            .call()

        byte[] secretBytes = testSecret.getBytes(StandardCharsets.UTF_8)
        SecretKeySpec signingKey = new SecretKeySpec(secretBytes, "HmacSHA256")
        
        def claims = Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(result.token)
            .getPayload()

        then:
        claims.get('tenantId') == 'TENANT_001'
    }

    def "issue#JwtAssertion includes optional storeId claim"() {
        when:
        def result = ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .parameters([storeId: 'STORE_123'])
            .call()

        byte[] secretBytes = testSecret.getBytes(StandardCharsets.UTF_8)
        SecretKeySpec signingKey = new SecretKeySpec(secretBytes, "HmacSHA256")
        
        def claims = Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(result.token)
            .getPayload()

        then:
        claims.get('storeId') == 'STORE_123'
    }

    def "issue#JwtAssertion includes additional custom claims"() {
        when:
        def result = ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .parameters([
                additionalClaims: [
                    customField1: 'value1',
                    customField2: 123
                ]
            ])
            .call()

        byte[] secretBytes = testSecret.getBytes(StandardCharsets.UTF_8)
        SecretKeySpec signingKey = new SecretKeySpec(secretBytes, "HmacSHA256")
        
        def claims = Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(result.token)
            .getPayload()

        then:
        claims.get('customField1') == 'value1'
        claims.get('customField2') == 123
    }

    def "issue#JwtAssertion fails when not authenticated"() {
        setup:
        ec.user.logoutUser()

        when:
        ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .call()

        then:
        thrown(org.moqui.BaseException)
    }

    def "issue#JwtAssertion fails when secret not configured"() {
        setup:
        String savedSecret = System.getProperty('moqui.assertion.secret')
        System.clearProperty('moqui.assertion.secret')

        when:
        ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .call()

        then:
        thrown(org.moqui.BaseException)

        cleanup:
        if (savedSecret) {
            System.setProperty('moqui.assertion.secret', savedSecret)
        }
    }

    def "issue#JwtAssertion fails when assertions disabled"() {
        setup:
        System.setProperty('moqui.assertion.enabled', 'false')

        when:
        ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .call()

        then:
        thrown(org.moqui.BaseException)

        cleanup:
        System.setProperty('moqui.assertion.enabled', 'true')
    }

    def "get#AssertionConfig returns configuration without secret"() {
        when:
        def result = ec.service.sync()
            .name("durion.positivity.AssertionServices.get#AssertionConfig")
            .call()

        then:
        result.enabled == true
        result.issuer == 'test-moqui'
        result.audience == 'api-gateway:test'
        result.ttlSeconds == 300
        result.secretConfigured == true
        // Secret value should NOT be returned
        !result.containsKey('secret')
    }

    def "issue#JwtAssertion enforces TTL bounds"() {
        setup:
        // Try setting TTL outside bounds
        System.setProperty('moqui.assertion.ttl', '10')  // Below minimum 60

        when:
        def result = ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .call()

        byte[] secretBytes = testSecret.getBytes(StandardCharsets.UTF_8)
        SecretKeySpec signingKey = new SecretKeySpec(secretBytes, "HmacSHA256")
        
        def claims = Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(result.token)
            .getPayload()

        // Should be clamped to minimum (60 seconds)
        def ttl = (claims.getExpiration().time - claims.getIssuedAt().time) / 1000

        then:
        ttl >= 60  // Minimum bound enforced

        cleanup:
        System.setProperty('moqui.assertion.ttl', '300')
    }

    def "issued tokens are unique (different jti each call)"() {
        when:
        def result1 = ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .call()
        def result2 = ec.service.sync()
            .name("durion.positivity.AssertionServices.issue#JwtAssertion")
            .call()

        then:
        result1.jti != result2.jti
        result1.token != result2.token
    }
}
