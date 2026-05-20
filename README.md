# Cyber Report Generator

A professional cybersecurity report generator that produces detailed PDF reports from security tool output.

## Report Types

| Report | Input | Use Case |
|--------|-------|----------|
| Penetration Test | nmap, nikto, dirb output | Pentest engagements |
| SOC Incident | JSON incident data | Security incident response |

## Quick Start

### Install dependencies
pip install -r requirements.txt

### Generate a Penetration Test Report
python main.py pentest --target "192.168.1.1" --analyst "Your Name" --nmap samples/nmap_output.txt --nikto samples/nikto_output.txt --output reports/pentest_report.pdf

### Generate a SOC Incident Report
python main.py soc --incident-file samples/incident.json --analyst "Your Name" --output reports/soc_report.pdf

## Sample Files

The samples/ directory contains example input files to test the tool:
- samples/nmap_output.txt - Example nmap scan output
- samples/nikto_output.txt - Example nikto scan output
- samples/incident.json - Example SOC incident data

## Report Features

- Professional cover page with confidentiality marking
- Executive summary with severity breakdown table
- Detailed findings with severity badges (Critical/High/Medium/Low)
- Risk descriptions and specific remediation steps
- Incident timeline, IOCs, and response actions (SOC reports)
- Prioritized recommendations

## Project Structure

- main.py - CLI entry point
- src/parsers.py - Parse tool output into structured findings
- src/report_generator.py - PDF report generation
- samples/ - Example input files
- reports/ - Generated reports output directory

## Tech Stack

Python, fpdf2, Click, python-docx

## Legal

For authorized security assessments only.
Built by @TsongaKing
