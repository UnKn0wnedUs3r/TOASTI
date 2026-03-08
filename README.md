# TOASTI
Toasti — Template Injection & OS Injection Scanner Tool

Toasti is a modular Python-based web vulnerability scanner designed to detect Server-Side Template Injection (SSTI) and OS Command Injection vulnerabilities across different types of web applications.

The tool supports traditional HTML websites, Single Page Applications (SPA), and JSON API-based systems, making it suitable for testing modern web applications.

Toasti was developed as an academic security project to demonstrate how automated scanners discover injection points, test vulnerabilities, and generate structured vulnerability reports.

# Features
Multi-Architecture Crawling

Toasti supports three types of web applications:

HTML websites — Crawls links and extracts HTML forms

Single Page Applications (SPA) — Discovers API endpoints from JavaScript files

JSON API systems — Detects endpoints using OpenAPI / Swagger discovery

This allows Toasti to scan both traditional and modern web architectures.

# SSTI Detection (5 Template Engines)

Toasti supports SSTI testing for five different template engines:

 Engine	Common Frameworks
Jinja2	Python Flask / Django
Twig	PHP Symfony
FreeMarker	Java Spring
Velocity	Java applications
Mustache	NodeJS / Java

# OS Command Injection Detection
Supports both windows and linux system
Supports both Os injections and Blind OS injection testing 

# Other Functions 
Reflection Detection

Toasti includes a reflection scanner to identify parameters where user input is returned in the response.

This helps identify potential injection points before running deeper vulnerability tests.

Authentication Support

Toasti supports authenticated scanning.

It can perform login through:

HTML form login

JSON API login

Vulnerability Explanation

Toasti includes built-in vulnerability descriptions and recommendations for detected issues.

Export functions 

User can export scan result as TXT file 

# Disclaimer

This tool is intended for educational and authorized security testing purposes only.

Do not use this tool against systems without permission.

# Author

Developed as part of a web security project.
