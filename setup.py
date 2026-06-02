#!/usr/bin/env python3
"""
Nucleon - Behavioral DNA Fingerprinting Engine v4.0
Academic Research Project: Malware Detection through Behavioral Genomics
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="nucleon",
    version="4.0.0",
    author="KuraTi Security Research",
    author_email="research@kurati.io",
    description="Behavioral DNA Fingerprinting Engine for Malware Detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kurati/nucleon",
    packages=find_packages(include=[
        "core", "core.*",
        "dna_engine", "dna_engine.*",
        "dna_engine.samples", "dna_engine.samples.*",
        "utils", "utils.*",
        "database", "database.*",
        "sandbox", "sandbox.*",
        "yara_engine", "yara_engine.*",
        "vector_db", "vector_db.*",
        "binary_analysis", "binary_analysis.*",
        "ast_analyzer", "ast_analyzer.*",
    ]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: Academic Free License (AFL)",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "nucleon-gui=main:main",
            "nucleon-stress-test=dna_engine.zen_stress_test_v4:main",
            "nucleon-sandbox=sandbox.sandbox_runner:main",
            "nucleon-analyze=binary_analysis.binary_scanner:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
