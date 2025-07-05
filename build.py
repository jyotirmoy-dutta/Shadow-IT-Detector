#!/usr/bin/env python3
"""
Build script for Shadow IT Detector
Creates standalone executables for different platforms
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a command and return the result"""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    
    print(f"Success: {result.stdout}")
    return True

def install_pyinstaller():
    """Install PyInstaller if not already installed"""
    try:
        import PyInstaller
        print("PyInstaller already installed")
        return True
    except ImportError:
        print("Installing PyInstaller...")
        return run_command([sys.executable, "-m", "pip", "install", "pyinstaller"])

def clean_build_dirs():
    """Clean build and dist directories"""
    dirs_to_clean = ["build", "dist", "__pycache__"]
    
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            print(f"Cleaning {dir_name}...")
            shutil.rmtree(dir_name)
    
    # Clean .spec files
    for spec_file in Path(".").glob("*.spec"):
        spec_file.unlink()

def build_executable(target="main", platform_name=None):
    """Build executable for the specified target"""
    
    # Determine platform
    if platform_name is None:
        platform_name = platform.system().lower()
    
    print(f"Building {target} for {platform_name}...")
    
    # Base PyInstaller command
    cmd = [
        "pyinstaller",
        "--onefile",
        "--windowed" if platform_name == "windows" else "--console",
        "--name", f"shadowit-{target}",
        "--add-data", "data:data",
        "--add-data", "config.yaml:.",
        "--hidden-import", "psutil",
        "--hidden-import", "rich",
        "--hidden-import", "yaml",
        "--hidden-import", "schedule",
        "--hidden-import", "requests",
        "--hidden-import", "flask",
        "--hidden-import", "sqlite3",
        "--hidden-import", "winreg" if platform_name == "windows" else "dummy",
    ]
    
    # Platform-specific options
    if platform_name == "windows":
        cmd.extend([
            "--icon", "assets/icon.ico" if os.path.exists("assets/icon.ico") else "",
        ])
    elif platform_name == "darwin":
        cmd.extend([
            "--icon", "assets/icon.icns" if os.path.exists("assets/icon.icns") else "",
        ])
    
    # Add the target script
    cmd.append(f"detector/{target}.py")
    
    # Remove empty strings
    cmd = [arg for arg in cmd if arg]
    
    return run_command(cmd)

def build_all():
    """Build all executables"""
    print("Building Shadow IT Detector executables...")
    
    # Install PyInstaller
    if not install_pyinstaller():
        print("Failed to install PyInstaller")
        return False
    
    # Clean previous builds
    clean_build_dirs()
    
    # Build targets
    targets = ["main", "agent_mode", "web_dashboard"]
    platform_name = platform.system().lower()
    
    success_count = 0
    for target in targets:
        if build_executable(target, platform_name):
            success_count += 1
        else:
            print(f"Failed to build {target}")
    
    print(f"\nBuild complete: {success_count}/{len(targets)} targets built successfully")
    
    # List built executables
    if os.path.exists("dist"):
        print("\nBuilt executables:")
        for exe in Path("dist").glob("*"):
            print(f"  - {exe}")
    
    return success_count == len(targets)

def build_docker():
    """Build Docker image"""
    print("Building Docker image...")
    
    # Create Dockerfile if it doesn't exist
    dockerfile_content = """
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs reports

# Expose port for web dashboard
EXPOSE 5000

# Set environment variables
ENV PYTHONPATH=/app

# Default command
CMD ["python", "-m", "detector.main"]
"""
    
    with open("Dockerfile", "w") as f:
        f.write(dockerfile_content)
    
    # Build Docker image
    return run_command(["docker", "build", "-t", "shadowit-detector", "."])

def main():
    """Main build function"""
    if len(sys.argv) < 2:
        print("Usage: python build.py [all|executable|docker|clean]")
        print("  all         - Build all executables")
        print("  executable  - Build single executable")
        print("  docker      - Build Docker image")
        print("  clean       - Clean build directories")
        return
    
    command = sys.argv[1]
    
    if command == "all":
        build_all()
    elif command == "executable":
        target = sys.argv[2] if len(sys.argv) > 2 else "main"
        build_executable(target)
    elif command == "docker":
        build_docker()
    elif command == "clean":
        clean_build_dirs()
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main() 