# Log Analysis Script

This Python script analyzes web server log files to extract and analyze key information, helping to detect suspicious activity and gain insights into user behavior.

---

## Features

The script performs the following tasks:
1. **Count Requests per IP Address**:
   - Identifies all unique IP addresses from the log file.
   - Counts how many times each IP has made a request.
   - Displays the counts in descending order.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Analyzes the log to determine which endpoints (URLs or paths) were accessed most frequently.
   - Provides the name of the top endpoint and the total number of times it was accessed.

3. **Detect Suspicious Activity**:
   - Detects repeated failed login attempts to flag potential brute force attacks:
     - Scans for error entries (e.g., HTTP 401 or messages like "Invalid credentials").
     - Highlights IPs exceeding a customizable threshold for failed attempts (default is 10).

4. **Output Results**:
   - Outputs the analysis directly in the terminal.
   - Saves findings in a structured CSV file (log_analysis_results.csv) with the following sections:
     - **Requests per IP**
     - **Most Accessed Endpoint**
     - **Suspicious Activity**

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/ankithar671/VRV_Security-s_Python_Intern_Assignment.git
   cd VRV_Security-s_Python_Intern_Assignment
