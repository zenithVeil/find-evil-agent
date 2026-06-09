# Find Evil Agent 

An autonomous AI-powered cybersecurity incident redsponse agent built for the SANS FIND EVIL! Hackathon.

## What it does
- Analyzes system logs for suspicious activity
- Self-corrects false positives automatically
- Generates professional incident response reports

## How to run
1. Clone this repo
2. Install dependencies: `pip install groq python-dotenv`
3. Add your GROQ_API_KEY to `.env` file
4. Run: `python agent.py`

## Requirements
- Python 3.12+
- Groq API key (free at groq.com)

## License
MIT

## Security Considerations
- API keys stored in `.env` file (never commit to GitHub)
- Input sanitization applied to prevent prompt injection
- Log entries sanitized before AI analysis

## Known Limitations
- Authentication system not implemented (single user only)
- Basic prompt injection protection (pattern matching)
- Designed for log file analysis only (not real-time monitoring)

## Future Improvements
- Add user authentication
- Implement real-time log monitoring
- Expand to more evidence types (memory, network captures)

## Running Locally on SIFT Workstation
1. Install SIFT from https://www.sans.org/tools/sift-workstation/
2. Clone: git clone https://github.com/zenithVeil/find-evil-agent
3. Install: pip3 install groq python-dotenv --break-system-packages
4. Add key: echo "GROQ_API_KEY=your_key" > .env
5. Run: python3 agent.py

## Evidence Dataset
Real Apache error logs from SIFT Workstation /var/log/apache2/error.log
Contains real web attacks — directory traversal, port scanning, unauthorized access
