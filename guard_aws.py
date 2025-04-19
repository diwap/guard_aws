"""
main.py

This module serves as the entry point for the application. It imports the `app` function
from the `commands` module and executes it when the script is run directly.

Usage:
    Run this script directly to start the application.

Example:
    python main.py
"""
from guard_aws.commands import app


if __name__ == "__main__":
    app()
