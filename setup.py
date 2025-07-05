from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="shadowit-detector",
    version="1.0.0",
    author="Shadow IT Detector Team",
    author_email="security@example.com",
    description="A comprehensive Shadow IT detection tool for enterprise environments",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/shadowit-detector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Monitoring",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "web": [
            "flask>=2.0",
            "flask-cors>=3.0",
        ],
        "monitoring": [
            "schedule>=1.2",
        ],
    },
    entry_points={
        "console_scripts": [
            "shadowit=detector.main:main",
            "shadowit-agent=detector.agent_mode:main",
            "shadowit-dashboard=detector.web_dashboard:main",
        ],
    },
    include_package_data=True,
    package_data={
        "detector": [
            "data/*.csv",
            "templates/*.html",
        ],
    },
    keywords="security, shadow-it, monitoring, enterprise, saas, detection",
    project_urls={
        "Bug Reports": "https://github.com/your-org/shadowit-detector/issues",
        "Source": "https://github.com/your-org/shadowit-detector",
        "Documentation": "https://github.com/your-org/shadowit-detector/wiki",
    },
) 