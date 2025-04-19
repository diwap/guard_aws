# Project Overview

This project is a Python-based application that leverages several libraries and tools, including `boto3`, `typer`, and `rich`, to provide a robust command-line interface (CLI) for interacting with AWS services and other utilities.

## Features

- **AWS S3 Verification**: Includes functionality to verify and interact with AWS S3 buckets using the `boto3` library. See [verify/s3.py](verify/s3.py) for implementation details.
- **Command-Line Interface**: Built using the `typer` library to create a user-friendly CLI. The CLI supports rich text formatting and enhanced terminal output using the `rich` library.
- **Environment Management**: The project uses a virtual environment for dependency management, as seen in the `.env/` directory.

## File Structure

- **`main.py`**: The entry point of the application. This file initializes the CLI and orchestrates the application's functionality.
- **`commands.py`**: Contains the CLI commands and their logic.
- **`config.py`**: Handles configuration settings for the application.
- **`verify/s3.py`**: Implements AWS S3 verification logic.
- **`.env/`**: Virtual environment directory containing dependencies like `boto3`, `typer`, and `rich`.

## Dependencies

The project relies on the following Python libraries:

- `boto3`: For AWS SDK integration.
- `typer`: For building the CLI.
- `rich`: For enhanced terminal output.

Dependencies are listed in [requirements.txt](requirements.txt).

## Getting Started

1. **Set up the virtual environment**:
   ```bash
   python3 -m venv .env
   source .env/bin/activate