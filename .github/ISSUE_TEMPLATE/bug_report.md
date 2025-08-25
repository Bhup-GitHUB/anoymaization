---
name: Bug report
about: Create a report to help us improve
title: '[BUG] '
labels: ['bug', 'needs-triage']
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## Steps to Reproduce

1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## Expected Behavior

A clear and concise description of what you expected to happen.

## Actual Behavior

A clear and concise description of what actually happened.

## Environment Information

### System Information
- **Operating System**: [e.g. Ubuntu 22.04, RHEL 8]
- **Kernel Version**: [e.g. 5.15.0-56-generic]
- **Architecture**: [e.g. x86_64]

### Package Versions
- **clang**: [e.g. 14.0.0]
- **llvm**: [e.g. 14.0.0]
- **libbpf**: [e.g. 0.8.1]

### Project Version
- **Commit Hash**: [e.g. a1b2c3d]
- **Branch**: [e.g. main, develop]

## Error Messages and Logs

Please include any error messages, warnings, or logs that might help diagnose the issue:

```bash
# Command output
$ command_here
output_here

# System logs
$ dmesg | tail -20
log_output_here

# Application logs
$ journalctl -u service_name -f
log_output_here
```

## Configuration Files

If the issue is related to configuration, please include relevant configuration files:

```txt
# anonymization_config.txt
anonymize_srcmac_oui: yes
anonymize_srcmac_id: no
# ... rest of config
```

## Additional Context

Add any other context about the problem here, such as:
- When did this issue start occurring?
- Does it happen with all interfaces or specific ones?
- Are there any recent changes to your system?
- Can you reproduce this issue consistently?

## Screenshots

If applicable, add screenshots to help explain your problem.

## Possible Solutions

If you have any ideas about what might be causing this issue or how to fix it, please share them.

## Checklist

- [ ] I have searched existing issues to avoid duplicates
- [ ] I have provided all required environment information
- [ ] I have included error messages and logs
- [ ] I have tested with the latest version of the project
- [ ] I have tried the troubleshooting steps in the documentation

## Priority

Please indicate the priority of this issue:
- [ ] **Critical**: System crash or data loss
- [ ] **High**: Major functionality broken
- [ ] **Medium**: Minor functionality broken
- [ ] **Low**: Cosmetic issue or enhancement request
