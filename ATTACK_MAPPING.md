# ATT&CK Mapping

| Family | Detection Area | ATT&CK Technique | Reason |
| --- | --- | --- | --- |
| BlueHammer | Local privilege escalation | T1068 | Defender vulnerability abuse for elevated execution. |
| BlueHammer | SAM or hive access | T1003.002 | Credential material access from SAM or VSS paths. |
| BlueHammer | Service installation | T1543.003 | GUID-like service creation is part of the stronger execution chain. |
| RedSun | Local privilege escalation | T1068 | Defender behavior is abused for privileged file-write outcomes. |
| RedSun | Reparse or junction pivot | T1574.010 | File-path redirection behavior is central to the chain. |
| RedSun | SYSTEM execution pivot | T1055 | SYSTEM-level `conhost.exe` and related execution artifacts raise severity. |
| UnDefend | Defender degradation | T1562.001 | Security tooling availability is impaired through file, update, and service-health interference. |
| UnDefend | Configuration discovery and registry access | T1112 | Defender registry and service-state discovery are part of the observed behavior. |
| CrossFamily | BeigeBurrow tunneling | T1572,T1090 | Reverse-tunnel or proxy-like follow-on access materially raises severity. |
| CrossFamily | Recon commands | T1033,T1087 | Privilege and account-group discovery near suspicious tooling strengthens confidence. |
