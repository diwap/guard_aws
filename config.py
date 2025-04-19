"""
This module provides a factory class for creating AWS service clients using a specified AWS profile.

Classes:
    AWSClientFactory:
        A factory class for creating AWS service clients. It initializes a boto3 session
        using the AWS profile specified in the `AWS_PROFILE` environment variable. If the
        `AWS_PROFILE` environment variable is not set, an exception is raised. The class
        provides a method to create clients for various AWS services.

            __init__():
                Initializes the AWSClientFactory instance by creating a boto3 session
                with the specified AWS profile.
"""
from os import environ
from sys import exit as sys_exit

from boto3 import Session
from rich import print as rich_print


class AWSClientFactory:
    """
    A factory class for creating AWS service clients using a specified AWS profile.

    This class initializes a boto3 session using the AWS profile specified in the 
    environment variable `AWS_PROFILE`. If the `AWS_PROFILE` environment variable 
    is not set, an exception is raised. The factory provides a method to create 
    clients for various AWS services.

    Attributes:
        session (boto3.Session): The boto3 session initialized with the specified AWS profile.

    Methods:
        client(service_name: str) -> boto3.client:
            Creates and returns a boto3 client for the specified AWS service.
    """
    def __init__(self):
        profile = environ.get("AWS_PROFILE")
        if not profile:
            rich_print("[red][bold]AWS_PROFILE[/bold] is not set in the environment![/red]")
            sys_exit(1)
        self.session = Session(profile_name=profile)

    def client(self, service_name):
        """
        Creates and returns a low-level client representing the specified AWS service.

        Args:
            service_name (str): The name of the AWS service for which a client is to be created.

        Returns:
            botocore.client.BaseClient: A low-level client instance for the specified AWS service.
        """
        return self.session.client(service_name)
