# File Integrity Monitor using Hashing Algorithms

### Description
A File Integrity Monitor (FIM) is a security tool that tracks changes to critical system files by calculating and comparing hash values. Here's how it works:

- Initial Hash Calculation: When the system or files are first monitored, the FIM computes a cryptographic hash (e.g., MD5, SHA-256) for each file. This hash uniquely represents the file's current content.

- Ongoing Monitoring: The FIM periodically re-calculates the hash values of these files during operation.

- Change Detection: If any file is modified, even slightly, its hash value will change. The FIM detects this alteration by comparing the new hash with the original. If they differ, it raises an alert indicating a possible unauthorized change.

- Response: Upon detection, the system can log the change, notify administrators, or even trigger an automated response to investigate or revert the change.

### Languages & utilities
- Powershell

### Libraries & tools
- Get-FileHash
- FileSystemWatcher
- Send-MailMessage
- Windows Event Logs

### Environment
- Windows 11

## System Development Methodology

![Screenshot 2024-10-02 003259](https://github.com/user-attachments/assets/6b04d7aa-3303-4944-b4df-bb006f4dbc53)

