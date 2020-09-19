# Automated VCC Finding Script

This is part of the Assignment 2 for course COMP SCI 7412 Secure Software Engineering.

I assume that at least Python 3.8 (latest stable version) will be used for this project as there is no version requirement was imposed for this assignment
SyntaxError may raise if using an earlier version due to the following most recent new features:

* Type Hint (weak typing support): based on PEP 484, available from Python 3.5
* f-string (string interpolation): based on PEP 498, available from Python 3.6
* Walrus Operator (assignment expression): based on PEP 572, available from Python 3.8

The heuristics implemented in the is based on _[VCCFinder: Finding Potential Vulnerabilities in Open-Source Projects to Assist Code Audits](https://dl.acm.org/doi/10.1145/2810103.2813604)_.

It's important to run `/usr/bin/env python3 -m pip install -r requirements.txt` before executing the script.

`repo.json` is a configuration file to be read by the script.

`output.json` is the raw data for the report and the submitted table.
