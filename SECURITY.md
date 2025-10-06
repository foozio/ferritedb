# Security Policy

## Supported Versions

We actively support the following versions of FerriteDB with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| 0.x.x   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in FerriteDB, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please:

1. **Email**: Send details to security@ferritedb.dev (if available) or create a private security advisory on GitHub
2. **GitHub Security Advisory**: Use GitHub's private vulnerability reporting feature
3. **Encrypted Communication**: For sensitive issues, use our PGP key (available on request)

### What to Include

Please provide as much information as possible:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact and attack scenarios
- **Reproduction**: Step-by-step instructions to reproduce
- **Affected Versions**: Which versions are affected
- **Suggested Fix**: If you have ideas for a fix
- **Your Contact**: How we can reach you for follow-up

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Status Updates**: Weekly until resolved
- **Fix Timeline**: Depends on severity (see below)

### Severity Levels

#### Critical (CVSS 9.0-10.0)
- **Response Time**: 24-48 hours
- **Fix Timeline**: 1-7 days
- **Examples**: Remote code execution, authentication bypass

#### High (CVSS 7.0-8.9)
- **Response Time**: 48-72 hours
- **Fix Timeline**: 1-2 weeks
- **Examples**: Privilege escalation, data exposure

#### Medium (CVSS 4.0-6.9)
- **Response Time**: 1 week
- **Fix Timeline**: 2-4 weeks
- **Examples**: Information disclosure, DoS

#### Low (CVSS 0.1-3.9)
- **Response Time**: 2 weeks
- **Fix Timeline**: Next regular release
- **Examples**: Minor information leaks

## Security Best Practices

### For Users

#### Production Deployment

1. **Change Default Secrets**
   ```bash
   # Generate secure JWT secret
   openssl rand -base64 64
   
   # Set in environment or config
   export FERRITEDB_AUTH_JWT_SECRET="your-secure-secret"
   ```

2. **Use HTTPS**
   - Always use TLS in production
   - Configure proper SSL certificates
   - Use HSTS headers

3. **Database Security**
   ```bash
   # Secure file permissions
   chmod 600 data/ferritedb.db
   
   # Regular backups
   sqlite3 data/ferritedb.db ".backup backup.db"
   ```

4. **Network Security**
   - Use firewalls to restrict access
   - Consider VPN for admin access
   - Monitor access logs

5. **Regular Updates**
   ```bash
   # Check for updates
   ferritedb --version
   
   # Update to latest version
   cargo install ferritedb --force
   ```

#### Configuration Security

```toml
# ferritedb.toml - Production configuration
[server]
host = "127.0.0.1"  # Bind to localhost only
port = 8090

[auth]
jwt_secret = "${JWT_SECRET}"  # Use environment variable
token_ttl = 900               # 15 minutes
refresh_ttl = 86400          # 1 day
password_min_length = 12     # Strong passwords

[server.rate_limit]
requests_per_minute = 60     # Rate limiting
burst_size = 10

[features]
metrics = false              # Disable if not needed
```

#### User Management

1. **Admin Accounts**
   - Use strong, unique passwords
   - Enable 2FA when available
   - Regularly rotate credentials
   - Limit admin user count

2. **Regular Users**
   - Enforce password policies
   - Monitor user activity
   - Remove inactive accounts
   - Use role-based access control

#### File Storage Security

1. **Local Storage**
   ```bash
   # Secure directory permissions
   chmod 750 data/storage
   chown ferritedb:ferritedb data/storage
   ```

2. **S3/Cloud Storage**
   - Use IAM roles with minimal permissions
   - Enable bucket encryption
   - Configure CORS properly
   - Monitor access logs

### For Developers

#### Secure Coding Practices

1. **Input Validation**
   ```rust
   // Always validate user input
   pub fn validate_collection_name(name: &str) -> Result<(), ValidationError> {
       if name.is_empty() || name.len() > 64 {
           return Err(ValidationError::InvalidLength);
       }
       
       if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
           return Err(ValidationError::InvalidCharacters);
       }
       
       Ok(())
   }
   ```

2. **SQL Injection Prevention**
   ```rust
   // Use parameterized queries
   let user = sqlx::query_as!(
       User,
       "SELECT * FROM users WHERE email = ?",
       email  // Automatically escaped
   )
   .fetch_optional(&pool)
   .await?;
   ```

3. **Authentication**
   ```rust
   // Use secure password hashing
   use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
   
   let argon2 = Argon2::default();
   let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
   ```

4. **Authorization**
   ```rust
   // Check permissions before operations
   if !user.can_access_collection(&collection) {
       return Err(AuthError::Forbidden);
   }
   ```

#### Security Testing

1. **Automated Security Scanning**
   ```bash
   # Dependency vulnerability scanning
   cargo audit
   
   # Static analysis
   cargo clippy -- -W clippy::all
   
   # Format checking
   cargo fmt --check
   ```

2. **Manual Security Testing**
   - Test authentication bypass attempts
   - Verify authorization controls
   - Test input validation boundaries
   - Check for information disclosure

#### Dependency Management

1. **Regular Updates**
   ```bash
   # Check for outdated dependencies
   cargo outdated
   
   # Update dependencies
   cargo update
   
   # Audit for vulnerabilities
   cargo audit
   ```

2. **Dependency Review**
   - Review new dependencies before adding
   - Prefer well-maintained crates
   - Monitor security advisories
   - Use `cargo deny` for policy enforcement

## Security Features

### Built-in Security

1. **Authentication**
   - Argon2id password hashing
   - JWT token-based authentication
   - Configurable token expiration
   - Refresh token rotation

2. **Authorization**
   - Role-based access control
   - Collection-level permissions
   - Rule-based access control
   - Field-level security

3. **Input Validation**
   - JSON Schema validation
   - SQL injection prevention
   - XSS protection
   - File upload validation

4. **Security Headers**
   - CORS configuration
   - Content Security Policy
   - X-Frame-Options
   - X-Content-Type-Options

5. **Rate Limiting**
   - Configurable rate limits
   - Per-IP tracking
   - Burst protection
   - Authentication rate limiting

### Audit Logging

FerriteDB logs security-relevant events:

```rust
// Example audit log entry
{
    "timestamp": "2024-01-15T10:30:00Z",
    "level": "WARN",
    "event": "authentication_failed",
    "user_email": "user@example.com",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "request_id": "req_123456"
}
```

Monitor these logs for:
- Failed authentication attempts
- Privilege escalation attempts
- Unusual access patterns
- Administrative actions

## Incident Response

### If You Suspect a Breach

1. **Immediate Actions**
   - Change all administrative passwords
   - Rotate JWT secrets
   - Review access logs
   - Isolate affected systems

2. **Investigation**
   - Preserve logs and evidence
   - Identify scope of compromise
   - Determine attack vector
   - Assess data exposure

3. **Recovery**
   - Apply security patches
   - Restore from clean backups
   - Update security configurations
   - Monitor for continued threats

4. **Communication**
   - Notify affected users
   - Report to authorities if required
   - Document lessons learned
   - Update security procedures

## Security Hardening Checklist

### System Level
- [ ] Operating system is up to date
- [ ] Firewall is configured and active
- [ ] SSH is secured (key-based auth, non-standard port)
- [ ] Fail2ban or similar intrusion prevention
- [ ] Regular security updates applied

### Application Level
- [ ] Default credentials changed
- [ ] Strong JWT secret configured
- [ ] HTTPS/TLS enabled
- [ ] Security headers configured
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] File permissions secured
- [ ] Database access restricted

### Monitoring
- [ ] Log monitoring configured
- [ ] Intrusion detection system
- [ ] Performance monitoring
- [ ] Backup verification
- [ ] Security scanning scheduled

## Resources

### Security Tools
- [cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit): Vulnerability scanning
- [cargo-deny](https://github.com/EmbarkStudios/cargo-deny): Dependency policy enforcement
- [sqlx](https://github.com/launchbadge/sqlx): Compile-time SQL checking
- [OWASP ZAP](https://www.zaproxy.org/): Web application security testing

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [SQLite Security](https://www.sqlite.org/security.html)
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)

---

Security is a shared responsibility. By following these guidelines and reporting vulnerabilities responsibly, we can keep FerriteDB secure for everyone.