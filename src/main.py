import re
import json
import os
import sys

# Regex Patterns
EMAIL_PAT = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
CARD_PAT = re.compile(r'\b(?:\d[- ]?){13,19}\b')
URL_PAT = re.compile(r'\bhttps?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(?:/[^\s]*)?\b')
PHONE_PAT = re.compile(r'\+?[1-9]\d{0,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}')

def is_unsafe(text):
    # Detect common SQL Injection and XSS signature patterns
    pattern = r"<script|javascript:|UNION\s+SELECT|;\s*DROP|'\s*OR\s*|--"
    return bool(re.search(pattern, text, re.IGNORECASE))

def luhn_check(num):
    # Standard Luhn Mod 10 checksum algorithm
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) < 13: return False
    odd_sum = sum(digits[-1::-2])
    even_sum = sum(sum(divmod(d * 2, 10)) for d in digits[-2::-2])
    return (odd_sum + even_sum) % 10 == 0

def mask_email(email):
    local, domain = email.split('@', 1)
    return f"{local[0]}***{local[-1]}@{domain}" if len(local) > 2 else f"***@{domain}"

def mask_card(card):
    digits = ''.join(c for c in card if c.isdigit())
    return f"****-****-****-{digits[-4:]}"

def is_phone_substring(line, start, end):
    # Check if match is part of a longer digit sequence (like a credit card)
    if start > 0 and line[start-1] in ' -.' and line[max(0, start-2)].isdigit():
        return True
    if end < len(line) and line[end] in ' -.' and line[min(len(line)-1, end+1)].isdigit():
        return True
    return False

def process_log(input_path, output_path):
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found.")
        sys.exit(1)
        
    results = {"emails": [], "credit_cards": [], "urls": [], "phone_numbers": []}
    
    with open(input_path, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()[:1000] # Safe line buffer size
            line_unsafe = is_unsafe(line)
            
            # Emails
            for m in EMAIL_PAT.finditer(line):
                email = m.group()
                category = "General"
                if email.endswith("@alueducation.com"): category = "ALU Official"
                elif email.endswith("@alumni.alueducation.com"): category = "ALU Alumni"
                elif email.endswith("@si.alueducation.com"): category = "ALU SI"
                
                results["emails"].append({
                    "line": idx,
                    "masked_value": mask_email(email),
                    "category": category,
                    "is_valid": len(email) <= 254 and len(email.split('@')[0]) <= 64,
                    "is_safe": not line_unsafe
                })
                
            # Credit Cards
            for m in CARD_PAT.finditer(line):
                card = m.group()
                results["credit_cards"].append({
                    "line": idx,
                    "masked_value": mask_card(card),
                    "is_valid": luhn_check(card),
                    "is_safe": not line_unsafe
                })
                
            # URLs
            for m in URL_PAT.finditer(line):
                url = m.group()
                results["urls"].append({
                    "line": idx,
                    "value": "[REDACTED]" if line_unsafe or "@" in url else url,
                    "is_valid": len(url) <= 2048,
                    "is_safe": not line_unsafe and "@" not in url
                })
                
            # Phone Numbers
            for m in PHONE_PAT.finditer(line):
                if is_phone_substring(line, m.start(), m.end()):
                    continue
                phone = m.group()
                clean_digits = ''.join(c for c in phone if c.isdigit())
                results["phone_numbers"].append({
                    "line": idx,
                    "value": phone,
                    "is_valid": 7 <= len(clean_digits) <= 15,
                    "is_safe": not line_unsafe
                })
                
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as out_f:
        json.dump(results, out_f, indent=4)
    print(f"Extraction complete. Output saved to {output_path}")

def run_tests():
    assert mask_email("student@alueducation.com") == "s***t@alueducation.com"
    assert luhn_check("4111111111111111") is True
    assert luhn_check("4111111111111112") is False
    assert is_unsafe("' OR 1=1") is True
    assert is_unsafe("normal text") is False
    print("All unit tests passed successfully!")

if __name__ == "__main__":
    run_tests()
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    process_log(os.path.join(base_dir, "input", "raw-text.txt"), os.path.join(base_dir, "output", "sample-output.json"))
