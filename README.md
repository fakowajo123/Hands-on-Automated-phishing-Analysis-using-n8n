# Hands-on-Automated-phishing-Analysis-using-n8n
Developed an automated phishing analysis system that parses emails, extracts embedded links, and validates them against URLscan.io, URLhaus, and VirusTotal. The tool generates a detailed threat report[...]

---

## Introduction

Email remains one of the most common attack vectors for phishing campaigns. Security teams often face challenges in rapidly analyzing suspicious emails due to manual link inspection and delayed notifi[...]

The system ingests incoming Outlook emails, parses messages for indicators of compromise, and checks embedded URLs against URLscan.io and VirusTotal using their APIs. Results are merged into a consoli[...]

This project highlights my skills in:

- Integrating cloud-based APIs (Outlook, Slack, VirusTotal, URLscan.io)
- Automating phishing analysis workflows using n8n
- Writing custom detection logic with JavaScript for indicator extraction
- Building scalable security reporting pipelines that support rapid incident response

---

## Table of Contents

- Setup and Prerequisites
- Architecture
- Workflow Layers
  - Step 1: Trigger & Scheduling
  - Step 2: Email Processing
  - Step 3: IOC Detection & URL Extraction
  - Step 4: Threat Intelligence Checks
  - Step 5: Report Generation
  - Step 6: Slack Notifications
- Configuration Details
- Sample Report
- Error Handling & Limitations
- Future Enhancements

---

## Setup and Prerequisites

- n8n (Cloud or self-hosted)
- Microsoft 365 / Outlook account with API access

API Keys:
- URLscan.io
- VirusTotal (v3)
- Slack Bot Token + Channel ID
- Slack App with `chat:write` scope enabled
- Basic JavaScript for IOC detection logic

---

## Architecture

The phishing analysis workflow follows a layered design:

1. **Trigger & Scheduling**: Workflow runs at scheduled intervals to poll Outlook for unread emails.
2. **Email Processing**: Unread emails are retrieved via Outlook API and marked as read.
3. **IOC Detection & URL Extraction**: JavaScript node scans message content for indicators of compromise (IOCs) such as suspicious links.
4. **Threat Intelligence Checks**: URLs are submitted to URLscan.io and VirusTotal for analysis.
5. **Report Generation**: Results are normalized, merged, and scored for severity.
6. **Slack Notifications**: A formatted phishing analysis report is posted to a dedicated Slack channel.

📸 *Insert workflow diagram screenshot here*

---

## Workflow Layers

### Step 1: Trigger & Scheduling

- Configure Schedule Trigger to run every X seconds/minutes.
- Ensures continuous monitoring without manual checks.

📸 *Insert screenshot of Schedule Trigger node here*

---

### Step 2: Email Processing

The email processing layer is responsible for securely and efficiently retrieving suspicious emails and ensuring each message is only processed once.

- **Outlook Node**: This node connects to the Outlook API to fetch unread messages from the configured mailbox. You can configure it to filter by folder, sender, or other metadata as needed. 
  - 📸 *Insert screenshot of Outlook node here (showing its configuration)*
- **Mark as Read Node**: After emails are retrieved, this node marks them as read in Outlook so they are not reprocessed in subsequent workflow runs. This is crucial for workflow integrity and to avoid redundant analysis.
  - 📸 *Insert screenshot of Mark as Read node here (showing its configuration)*

By separating these two nodes, the workflow maintains a clear audit trail of which emails have been analyzed, and supports scalable processing for large inboxes or high-frequency polling.

---

### Step 3: IOC Detection & URL Extraction

This layer breaks down the email analysis into manageable batches and uses custom logic for extracting indicators.

- **Split In Batches Node**: This node divides the retrieved emails into smaller batches, allowing the workflow to process one email at a time. This is essential for controlling the flow rate and ensuring that API rate limits are respected.
  - 📸 *Insert screenshot of Split In Batches node here (showing its configuration)*
- **JavaScript Node**: This node contains custom code to extract URLs and other indicators of compromise from the email body and headers. You can extend the logic to scan for specific phishing patterns, suspicious domains, and more.
  - 📸 *Insert screenshot of JavaScript node here (showing its extraction logic)*

The combination of splitting in batches and using targeted extraction logic ensures that each email is thoroughly analyzed, while maintaining efficiency and scalability.

---

### Step 4: Threat Intelligence Checks

- URLscan.io Node: Submits URL and retrieves scan results.
- VirusTotal Node: Submits URL and checks reputation.

📸 *Insert screenshot of URLscan.io node here*
📸 *Insert screenshot of VirusTotal node here*

---

### Step 5: Report Generation

- Merge Node: Combines results from both APIs.
- Code Node: Scores severity and prepares structured report.

📸 *Insert screenshot of Merge + Report Builder here*

---

### Step 6: Slack Notifications

- Slack Node: Sends report to a security channel.
- Provides real-time visibility for security teams.

📸 *Insert screenshot of Slack node here*

---

## Configuration Details

- Environment variables for API keys
- Rate limits for URLscan.io and VirusTotal
- Slack bot token setup and required scopes (`chat:write`)

---

## Sample Report

✉️ **Phishing Scan**  
Subject: Verify your account  
From: it-support@example.com  
Received: 2025-09-05

**Findings:**
• https://example.bad/phish — Severity: High | VT(mal:7/sus:2) | URLscan: malicious

📸 *Insert screenshot of Slack message output here*

---

## Error Handling & Limitations

- API rate limits (URLscan.io & VirusTotal)
- Requires network connectivity to external APIs
- Only scans links, not attachments (future improvement)

---

## Future Enhancements

- Add attachment scanning (sandbox integration)
- Forward results into SIEM for long-term storage
- Expand detection to include suspicious keywords and domains
- Add caching to avoid resubmitting known safe URLs; build this into it

---
