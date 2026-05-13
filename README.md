# Log Attack Detector

## What This Does
Detects brute force attacks by analyzing server log files. Counts failed login attempts per IP and alerts when a threshold is exceeded.

## Live Demo
**Try it instantly:** [Click here to run on OnlineGDB](https://onlinegdb.com/t532DWHJlO)

> No installation needed. The code includes sample log data. Just click Run!

## How It Works
1. Reads a log file (or uses embedded sample data)
2. Identifies failed login attempts
3. Groups failures by IP address
4. Flags IPs exceeding 5 failed attempts

## Sample Output
