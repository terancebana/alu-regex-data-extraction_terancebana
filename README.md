ALU Regex Data Extraction Project

This project uses Python and regex to extract useful information from messy text files.

The program can find:

Emails
Credit card numbers
URLs
Phone numbers

It also:

Checks if credit cards are valid
Masks sensitive information
Detects unsafe text like SQL injection or XSS
Saves results into a JSON file
Project Structure
project/
├── input/
│ └── raw-text.txt
├── output/
│ └── output.json
├── src/
│ └── main.py
└── README.md
How to Run

Open the project folder and run:

python3 src/main.py

The program will:

Read the text file
Extract data
Validate information
Save results into a JSON file
Regex Patterns Used
Emails
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
Credit Cards
(?:\d[ -]?){13,19}
URLs
https?://\S+
Phone Numbers
\+?\d[\d\s.-]{7,15}
Features
Extracts data using regex
Masks emails and credit cards
Uses the Luhn algorithm for card validation
Detects unsafe input
Generates JSON output
Example Output
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
Python
Regex
JSON
