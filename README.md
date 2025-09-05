# Hands-on-Automated-phishing-Analysis-using-n8n
Developed an automated phishing analysis system that parses emails, extracts embedded links, and validates them against URLscan.io, URLhaus, and VirusTotal. The tool generates a detailed threat report[...]

---

## Introduction

Email remains one of the most common attack vectors for phishing campaigns. Security teams often face challenges in rapidly analyzing suspicious emails due to manual link inspection and delayed notifi[...]

The system ingests incoming Outlook emails, parses messages for indicators of compromise, and checks embedded URLs against URLscan.io, VirusTotal, and URLhaus using their APIs. Results are merged into[...]

This project highlights my skills in:

- Integrating cloud-based APIs (Outlook, Slack, VirusTotal, URLscan.io, URLhaus)
- Automating phishing analysis workflows using n8n
- Writing custom detection logic with JavaScript for indicator extraction
- Building scalable security reporting pipelines that support rapid incident response

---

## Table of Contents

- [Setup and Prerequisites](#setup-and-prerequisites)
- [Architecture](#architecture)
- [Workflow Layers](#workflow-layers)
  - [Step 1: Trigger & Scheduling](#step-1-trigger--scheduling)
  - [Step 2: Email Processing](#step-2-email-processing)
  - [Step 3: IOC Detection & URL Extraction](#step-3-ioc-detection--url-extraction)
  - [Step 4: Threat Intelligence Checks](#step-4-threat-intelligence-checks)
  - [Step 5: Report Generation](#step-5-report-generation)
  - [Step 6: Slack Notifications](#step-6-slack-notifications)
- [Configuration Details](#configuration-details)
- [Sample Report](#sample-report)
- [Error Handling & Limitations](#error-handling--limitations)
- [Future Enhancements](#future-enhancements)

---

## Setup and Prerequisites

- n8n (Cloud or self-hosted)
- Microsoft 365 / Outlook account with API access

API Keys required:
- URLscan.io
- VirusTotal (v3)
- URLhaus
- Slack Bot Token + Channel ID
- Slack App with `chat:write` scope enabled
- Basic JavaScript for IOC detection logic

Environment setup steps:
1. Install n8n and connect your Outlook account using the n8n Microsoft node.
2. Generate and securely store API keys for URLscan.io, VirusTotal, and Slack.
3. Configure environment variables in n8n for API keys.
4. Add your Slack Bot to the target channel and ensure it has the `chat:write` scope.

---

## Architecture

The phishing analysis workflow follows a layered design:

1. **Trigger & Scheduling**: Workflow runs at scheduled intervals to poll Outlook for unread emails.
2. **Email Processing**: Unread emails are retrieved via Outlook API and marked as read.
3. **IOC Detection & URL Extraction**: JavaScript node scans message content for indicators of compromise (IOCs) such as suspicious links.
4. **Threat Intelligence Checks**: URLs are submitted to URLscan.io, VirusTotal, and URLhaus for analysis.
5. **Report Generation**: Results are normalized, merged, and scored for severity.
6. **Slack Notifications**: A formatted phishing analysis report is posted to a dedicated Slack channel.

![Workflow Layout](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Workflow%20Layout.png)

---

## Workflow Layers

### Step 1: Trigger & Scheduling

- Configure Schedule Trigger to run every X seconds/minutes.
- Ensures continuous monitoring without manual checks.
- You can set the schedule to run at intervals appropriate for your operational needs, e.g., every 5 minutes for active monitoring.

![Trigger & Scheduling](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Trigger%20%26%20Scheduling.png)

---

### Step 2: Email Processing

The email processing layer is responsible for securely and efficiently retrieving suspicious emails and ensuring each message is only processed once.

- **Outlook Node**: This node connects to the Outlook API to fetch unread messages from the configured mailbox. You can configure it to filter by folder, sender, or other metadata as needed.  
  - ![Outlook Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Email%20node.png)
- **Mark as Read Node**: After emails are retrieved, this node marks them as read in Outlook so they are not reprocessed in subsequent workflow runs. This is crucial for workflow integrity and to avoi[...]
  - ![Mark as Read Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Mark%20as%20read%20node.png)

By separating these two nodes, the workflow maintains a clear audit trail of which emails have been analyzed, and supports scalable processing for large inboxes or high-frequency polling.

---

### Step 3: IOC Detection & URL Extraction

This layer breaks down the email analysis into manageable batches and uses custom logic for extracting indicators.

- **Split In Batches Node**: This node divides the retrieved emails into smaller batches, allowing the workflow to process one email at a time. This is essential for controlling the flow rate and ensu[...]
  - ![Split In Batches Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/split%20in%20branches.png)
- **JavaScript Node**: This node contains custom code to extract URLs and other indicators of compromise from the email body and headers. You can extend the logic to scan for specific phishing pattern[...]
  - ![*JavaScript Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Javascript%20node.png)

#### **Has URL? Node**

- After extracting indicators of compromise (IOCs), the workflow implements a **Has URL?** check. This node acts as a filter, verifying if the current email batch contains any URLs before proceeding t[...]

- The **Has URL?** node is crucial for efficiency, preventing unnecessary API calls to URLscan.io and VirusTotal when no actionable URLs are present. Its inclusion supports scalable, high-throughput a[...]

**Workflow Illustration:**  
The visual workflow includes a clear sequence: Split In Batches → Find indicators of compromise → Has URL? → Threat intelligence checks.  
![Image 1: Workflow Screenshot](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Workflow%20Layout.png)

The screenshot above demonstrates the use of the Has URL? node (orange diamond), positioned after the indicator extraction logic. The flow continues to threat intelligence checks only if URLs are dete[...]
![Has URL? Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/URL%20checker.png)
The batch splitting and Has URL? logic together enable granular, targeted phishing analysis, minimizing false positives and processing overhead.

---

### Step 4: Threat Intelligence Checks

The threat intelligence layer leverages both URLscan.io and VirusTotal APIs, and involves multiple nodes for submitting URLs and retrieving detailed scan reports:

- **URLscan.io Nodes**:
  - **Scan URL Node**: Submits the extracted URL to URLscan.io for scanning.
  -  ![Scan URL Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/URL%20scan%20node.png)
  -  - **No Error? Node**: Checks if the scan completed without errors before proceeding to report generation. If errors are detected, the workflow skips or retries as appropriate.
  - ![No Error? Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/No%20error%20node.png)
  - **Wait Node**: Introduces a delay to ensure the scan completes before retrieving results.
  - ![Wait Node]()
  - **Get Report Node**: Fetches the final scan report, including malicious verdicts, screenshots, and metadata.
  - ![Get Report Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Url%20Get%20Report%20node.png)

- **VirusTotal Nodes**:
  - **Scan URL Node**: Sends the URL to VirusTotal for analysis.
  - ![Scan URL Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/VirusTotal%20scan%20node.png)
  - **Get Report Node**: Retrieves the comprehensive reputation report, showing the number of engines that flagged the URL as malicious or suspicious.
  - ![Get Report Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Virustotal%20Get%20report%20node.png)

- **URLhaus Node**:
  - **Scan URL Node**: Submits the URL to URLhaus database to check for known malicious URLs.
  - **Get Report Node**: Retrieves data about the URL’s presence in threat intelligence databases and any associated reputation or classification.

These dedicated "Get Report" nodes for each service guarantee that only finalized, complete scan results are used in the subsequent reporting stage. The inclusion of the **No Error?** node ensures tha[...]


---

### Step 5: Report Generation

- **Merge Node**: Combines results from all APIs, including verdicts, screenshots, and reputation scores.
![Merge Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Merge%20report%20Node.png)
---

### Step 6: Slack Notifications

- **Slack Node**: Sends report to a security channel with formatted message blocks, including subject, sender, findings, and severity.
- Provides real-time visibility for security teams, with actionable intelligence to respond to phishing threats.

![Slack Node](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Slack%20message%20node.png)
---

## Configuration Details

- Environment variables for API keys are set in the n8n environment for secure storage.
- Rate limits for URLscan.io, VirusTotal, and URLhaus should be respected; set workflow delays if needed.
- Slack bot token setup and required scopes (`chat:write`) must be configured in your Slack app settings.

Other configuration options:
- Adjust batch size for parallel processing of emails.
- Customize JavaScript extraction logic for additional phishing indicators.
- Set error handling options for API failures and rate limits.

---

## Sample Report

![Sample Report](https://github.com/fakowajo123/Hands-on-Automated-phishing-Analysis-using-n8n/blob/main/Screenshots/Sample%20report.png)

---

## Error Handling & Limitations

- API rate limits (URLscan.io, VirusTotal, URLhaus) may delay processing; implement retry logic if necessary.
- Requires network connectivity to external APIs; failures should trigger notification alerts.
- Only scans links, not attachments (future improvement planned for attachment sandboxing).
- If no URLs are found, the report will note "No indicators detected."
- The system relies on the accuracy of threat intelligence feeds, which may occasionally have false positives.
- Workflow can be extended to support additional threat feeds and indicators as needed.

---

## Future Enhancements

- Add attachment scanning (sandbox integration) to detect malware or credential harvesters in files.
- Forward results into SIEM for long-term storage and advanced correlation.
- Expand detection to include suspicious keywords and domains, such as impersonation attempts or brand abuse.
- Add caching to avoid resubmitting known safe URLs; build this into the workflow for efficiency.
- Integrate additional threat feeds (e.g., URLhaus, PhishTank) for broader coverage.
- Enable automated email quarantine or user notification for confirmed threats.
- Enhance reporting and dashboard integration for centralized threat visibility.

---
