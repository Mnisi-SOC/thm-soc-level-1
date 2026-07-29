# Phishing Analysis Fundamentals

## Overview

This room focused on understanding different types of phishing attacks and analysing email headers and email content to identify potential phishing indicators and security threats.

## Objectives

- Understand common phishing techniques.
- Learn how to safely analyse suspicious emails.
- Inspect email headers.
- Identify spoofed organisations.
- Identify the sender's email address.
- Extract forensic information from email headers.

## Tools Used

- `Thunderbird`
- `Linux Virtual Machine`
- `CyberChef`

## Types of Phishing

- `Phishing`: Email that impersonate a trusted entity to trick recipients into revealing sensitive information.
- `Smishing`: Phishing attacks conducted through text messages.
- `Vishing`: Phishing attacks carried out through voice calls.
- `Whaling`: A type of phishing that targets high-level executives.

## Safe Analysis

Before analysing the email, I followed safe analysis practices to prevent accidental interaction with potentially malicious content.

This included:

- Defanging URLs
- Defanging IP addresses
- Defanging email addresses
- Avoiding interaction with links or attachments

### Example

Original URL

```
http://www.suspiciousdomain.com
```

Defanged URL

```
hxxp://www[.]suspiciousdomain[.]com
```

## Investigation

I opened the provided email sample (`email3.eml`) in Thunderbird and viewed the email source to inspect the email headers.

During the investigation, I identified:

- The organisation being spoofed
- The sender's email address
- The defanged `X-Originating-IP`
- The mail server that generated the `Authentication-Results` header

The required information was obtained by examining the relevant email header fields.

![Email Source]()

## Key Takeaways

- Email headers contain valuable information for phishing investigations.
- Viewing the email source helps identify the true sender and routing information.
- Defanging indicators prevents accidental interaction with malicious content.
- Careful examination of email headers can reveal signs of phishing attempts.

## Skills Practiced

- Email header analysis
- Phishing investigation
- Safe malware analysis practices
- Indicator identification
- Email source inspection
