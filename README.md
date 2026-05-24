ALU Regex Data Extraction Project

A robust, Python-based utility designed to parse, extract, validate, and sanitize sensitive information from unstructured, messy text files using advanced Regular Expressions (Regex).

This tool is specifically designed to safely handle data by identifying key entities, validating financial identifiers, masking sensitive details, and detecting potential web application security threats such as SQL Injection (SQLi) and Cross-Site Scripting (XSS).

Features

Regex-Based Extraction: Efficiently scans raw text to identify emails, credit cards, URLs, and phone numbers.

Sensitive Data Masking: Automatically masks critical information (e.g., credit cards and emails) to preserve user privacy and maintain security compliance.

Credit Card Validation: Integrates the Luhn Algorithm (modulo 10 checksum) to verify the mathematical validity of extracted credit card numbers.

Security Threat Detection: Analyzes input strings to identify potentially malicious payloads, including SQL Injection and XSS vectors.

Structured JSON Output: Exports all parsed, validated, and classified data into a clean, structured JSON format for downstream processing or security auditing.

Project Structure

project/
├── input/
│ └── raw-text.txt
├── output/
│ └── output.json
├── src/
│ └── main.py
└── README.md

Regex Patterns Used

The application relies on highly optimized regular expressions to match target data types:

Data Type

Regular Expression Pattern

Emails

[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

Credit Cards

(?:\d[ -]?){13,19}

URLs

https?://\S+

Phone Numbers

\+?\d[\d\s.-]{7,15}

Installation & Usage

Prerequisites

Python 3.x

Running the Application

Ensure your messy source text is saved in input/raw-text.txt.

Open your terminal, navigate to the project directory, and execute the main script:

python3 src/main.py

The program will read the raw text, execute the extraction pipeline, perform validation/sanitization checks, and export the findings directly to output/output.json.

Example Output

The resulting output.json presents parsed data with corresponding line tracking, masked values, and safety indicators:

{
"emails": [
{
"line": 1,
"value": "j***@gmail.com",
"safe": true
}
]
}

Technologies Used

Language: Python 3

Libraries: - re

json
