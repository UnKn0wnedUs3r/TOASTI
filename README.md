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

SSTI Detection (5 Template Engines)

Toasti supports SSTI testing for five different template engines:

# Engine	Common Frameworks
Jinja2	Python Flask / Django
Twig	PHP Symfony
FreeMarker	Java Spring
Velocity	Java applications
Mustache	NodeJS / Java



