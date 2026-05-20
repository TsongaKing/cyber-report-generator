import re


NMAP_SEVERITY = {
    'ssh': ('Medium', 'SSH service exposed. Ensure strong authentication, disable root login, use key-based auth.'),
    'http': ('Medium', 'HTTP service exposed without encryption. Consider redirecting to HTTPS.'),
    'https': ('Info', 'HTTPS service running. Verify TLS version and cipher suites.'),
    'mysql': ('High', 'MySQL database port exposed. Should not be publicly accessible. Restrict to localhost only.'),
    'http-proxy': ('Medium', 'HTTP proxy service detected. Verify this is intentional and properly secured.'),
    'ftp': ('High', 'FTP service detected. FTP transmits credentials in plaintext. Replace with SFTP.'),
    'telnet': ('Critical', 'Telnet service detected. Transmits all data in plaintext. Disable immediately.'),
    'smb': ('High', 'SMB service exposed. Common target for lateral movement. Restrict access.'),
    'rdp': ('High', 'RDP exposed to network. High risk of brute force attacks. Restrict access.'),
    'default': ('Low', 'Service detected. Review if this port needs to be publicly accessible.')
}

NIKTO_PATTERNS = [
    (r'X-Frame-Options', 'High', 'Missing X-Frame-Options Header',
     'The X-Frame-Options HTTP response header is not present. This leaves the application vulnerable to clickjacking attacks where an attacker embeds the site in an invisible iframe.',
     'Add "Header always set X-Frame-Options DENY" to Apache configuration or equivalent for your web server.'),
    (r'X-Content-Type-Options', 'Medium', 'Missing X-Content-Type-Options Header',
     'The X-Content-Type-Options header is not set. This allows browsers to MIME-sniff responses away from the declared content-type, enabling certain attack vectors.',
     'Add "Header always set X-Content-Type-Options nosniff" to your web server configuration.'),
    (r'outdated|old version', 'Medium', 'Outdated Software Version Detected',
     'An outdated version of server software was detected. Outdated software may contain known vulnerabilities that have been publicly disclosed.',
     'Update all server software to the latest stable version. Subscribe to security advisories for your software stack.'),
    (r'phpinfo', 'High', 'PHP Info Page Exposed',
     'A phpinfo() page is publicly accessible. This page reveals sensitive server configuration including PHP version, loaded modules, file paths, and environment variables.',
     'Remove or restrict access to phpinfo.php immediately. This file should never be accessible in a production environment.'),
    (r'HttpOnly|httponly', 'High', 'Session Cookie Missing HttpOnly Flag',
     'The session cookie is set without the HttpOnly flag. This means the cookie can be accessed by client-side JavaScript, making it vulnerable to theft via Cross-Site Scripting (XSS) attacks.',
     'Set session.cookie_httponly = 1 in php.ini or use setcookie() with the httponly parameter set to true.'),
    (r'config|configuration', 'High', 'Sensitive Directory Exposed',
     'A configuration directory is publicly accessible. Configuration files may contain database credentials, API keys, and other sensitive information.',
     'Restrict access to configuration directories using web server access controls. Add "Require all denied" directives for sensitive directories.'),
    (r'admin|login', 'Medium', 'Administrative Interface Exposed',
     'An administrative login page is publicly accessible. This increases the attack surface and risk of brute force attacks.',
     'Restrict access to admin interfaces by IP address. Implement account lockout after failed attempts and enable MFA.'),
    (r'Server:', 'Low', 'Server Version Disclosure',
     'The web server is disclosing its version information in response headers. This helps attackers identify known vulnerabilities for the specific version.',
     'Configure ServerTokens Prod and ServerSignature Off in Apache, or equivalent for your web server.'),
]


def parse_nmap(output: str) -> dict:
    findings = []
    lines = output.split('\n')
    host = ''
    for line in lines:
        if 'Nmap scan report for' in line:
            host = line.replace('Nmap scan report for', '').strip()
        if '/tcp' in line or '/udp' in line:
            parts = line.split()
            if len(parts) >= 3:
                service = parts[2].lower()
                severity, description = NMAP_SEVERITY.get(service, NMAP_SEVERITY['default'])
                findings.append({
                    'port': parts[0],
                    'state': parts[1],
                    'service': parts[2],
                    'severity': severity,
                    'description': description
                })
    return {
        'tool': 'nmap',
        'host': host,
        'findings': findings,
        'total': len(findings)
    }


def parse_nikto(output: str) -> dict:
    findings = []
    lines = output.split('\n')
    for line in lines:
        if not line.strip().startswith('+') or 'Target IP' in line or 'Target Port' in line or 'Target Host' in line:
            continue
        line_clean = line.strip()
        matched = False
        for pattern, severity, title, description, remediation in NIKTO_PATTERNS:
            if re.search(pattern, line_clean, re.IGNORECASE):
                findings.append({
                    'title': title,
                    'raw': line_clean,
                    'severity': severity,
                    'description': description,
                    'remediation': remediation
                })
                matched = True
                break
        if not matched and len(line_clean) > 5:
            findings.append({
                'title': 'Additional Finding',
                'raw': line_clean,
                'severity': 'Low',
                'description': line_clean.replace('+ ', ''),
                'remediation': 'Review this finding and assess the potential impact on your environment.'
            })
    return {
        'tool': 'nikto',
        'findings': findings,
        'total': len(findings)
    }


def parse_dirb(output: str) -> dict:
    findings = []
    lines = output.split('\n')
    for line in lines:
        if '==> DIRECTORY' in line:
            path = line.replace('==> DIRECTORY:', '').strip()
            findings.append({
                'path': path,
                'type': 'Directory',
                'severity': 'Medium',
                'description': f'Directory {path} is accessible. Review if this should be publicly accessible.',
                'remediation': 'Restrict directory browsing and apply appropriate access controls.'
            })
        elif line.strip().startswith('+ ') and 'CODE:200' in line:
            findings.append({
                'path': line.strip(),
                'type': 'File',
                'severity': 'Low',
                'description': 'File or endpoint discovered during directory enumeration.',
                'remediation': 'Review if this resource should be publicly accessible.'
            })
    return {
        'tool': 'dirb',
        'findings': findings,
        'total': len(findings)
    }


def parse_soc_incident(data: dict) -> dict:
    return {
        'tool': 'soc_incident',
        'title': data.get('title', 'Security Incident'),
        'severity': data.get('severity', 'Medium'),
        'timeline': data.get('timeline', []),
        'affected_systems': data.get('affected_systems', []),
        'indicators': data.get('indicators', []),
        'response_actions': data.get('response_actions', []),
        'findings': [],
        'total': len(data.get('indicators', []))
    }


def assign_severity(count: int) -> str:
    if count == 0:
        return 'Low'
    elif count <= 3:
        return 'Medium'
    elif count <= 7:
        return 'High'
    return 'Critical'
