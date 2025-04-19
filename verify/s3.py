"""
Module: s3
This module provides functionality to verify and validate the configuration of Amazon S3 buckets.
It includes checks for public access settings, encryption at rest, IAM and bucket policies, 
lifecycle policies, and the use of bucket ARNs in IAM policies.
Classes:
    CheckS3: A class to perform various checks on S3 bucket configurations.
Dependencies:
    - rich: For printing styled output to the console.
    - botocore.exceptions.ClientError: For handling AWS client errors.
    - config.AWSClientFactory: A factory class to create AWS service clients.
"""
from rich import print as rich_print
from botocore.exceptions import ClientError

from guard_aws.config import AWSClientFactory


class CheckS3:
    """
    Class to check S3 bucket configurations.
    """
    def __init__(self, bucket):
        self.client = AWSClientFactory().client("s3")
        self.buckets = bucket or []

    def check(self):
        """
        Run all checks.
        """
        buckets = self.__get_buckets()
        for bucket in buckets:
            rich_print(f"\n[bold grey]=========== {bucket} ===============[/bold grey]")

            if not self.__check_if_bucket_exists(bucket):
                continue

            rich_print("[bold blue]Ensure 'Block public access' has been enabled on all S3 buckets (except if deploying a publicly accessible application/content)[/bold blue]")
            self.verify_block_public_access(bucket)

            rich_print("\n[bold blue]Ensure data is encrypted at rest using AWS KMS with Customer Managed Keys (Robert Half CMK)[/bold blue]")
            self.verify_encryption_at_rest(bucket)

            rich_print("\n[bold blue]Ensure IAM and bucket policies are used to control access to S3 buckets[/bold blue]")
            self.verify_iam_and_bucket_policies(bucket)

            rich_print("\n[bold blue]Ensure the Bucket ARN is used in an IAM policy to access the contents of the bucket (Do not use '*' principal)[/bold blue]")
            self.ensure_bucket_arn_in_iam_policy(bucket)

            rich_print("\n[bold blue]Ensure lifecycle policies have been configured to enforce business/regulatory requirements for data retention and disposal[/bold blue]")
            self.ensure_lifecycle_policies(bucket)


    def __get_buckets(self):
        """
        Retrieve the list of S3 bucket names.

        This method fetches the names of S3 buckets. If the `buckets` attribute is empty,
        it queries the AWS S3 service using the client to list all available buckets.
        Otherwise, it uses the pre-defined list of buckets from the `buckets` attribute.

        Returns:
            list: A list of S3 bucket names.
        """
        buckets = []
        if not self.buckets:
            response = self.client.list_buckets()
            buckets.extend([bucket['Name'] for bucket in response['Buckets']])
        else:
            buckets.extend(self.buckets)

        return buckets
    
    def __check_if_bucket_exists(self, bucket):
        """
        Checks if an S3 bucket exists.
        This method uses the AWS S3 client's `head_bucket` operation to determine 
        whether the specified bucket exists. If the bucket exists, the method 
        returns `True`. If the bucket does not exist or an error occurs, it 
        returns `False` and logs the appropriate error message.
        Args:
            bucket (str): The name of the S3 bucket to check.
        Returns:
            bool: `True` if the bucket exists, `False` otherwise.
        Raises:
            ClientError: If an AWS service-related error occurs.
            Exception: If any other unexpected error occurs.
        """
        try:
            self.client.head_bucket(Bucket=bucket)
            return True
        except ClientError as e:
            error_code = int(e.response['Error']['Code'])
            if error_code == 404:
                rich_print(f"[red]Bucket: [bold]{bucket}[/bold] does not exist![/red]")
            else:
                rich_print(f"[red]Error checking bucket [bold]{bucket}[/bold]: {e}[/red]")
            return False
        except Exception as e:
            rich_print(f"[yellow]Error checking bucket [bold]{bucket}[/bold][/yellow]: {e}")
            return False

    def verify_block_public_access(self, bucket):
        """
        Verify block public access settings for all S3 buckets.
        """
        try:
            response = self.client.get_public_access_block(Bucket=bucket)
            rich_print(f"[green]Bucket: [bold]{bucket}[/bold], Block Public Access:[/green] {response['PublicAccessBlockConfiguration']}")
        except Exception:
            rich_print(f"[yellow]Bucket: [bold]{bucket}[/bold] does not have public access block configuration.[/yellow]")
     

    def verify_encryption_at_rest(self, bucket):
        """
        Verify that data is encrypted at rest using AWS KMS with Customer Managed Keys.
        """
        response = self.client.get_bucket_encryption(Bucket=bucket)
        rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        for rule in rules:
            if rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'aws:kms':
                key_id = rule['ApplyServerSideEncryptionByDefault'].get('KMSMasterKeyID', '')
                if "RobertHalf" in key_id:
                    rich_print(f"[green]Bucket: [bold]{bucket}[/bold] is encrypted with Robert Half CMK.[/green]")
                else:
                    rich_print(f"[yellow]Bucket: [bold]{bucket}[/bold] is not encrypted with Robert Half CMK.[/yellow]")
            else:
                rich_print(f"[yellow]Bucket: [bold]{bucket}[/bold] is not using AWS KMS for encryption.[/yellow]")

    def verify_iam_and_bucket_policies(self, bucket):
        """
        Verify that IAM and bucket policies are used to control access to S3 buckets.
        """
        try:
            self.client.get_bucket_policy(Bucket=bucket)
            rich_print(f"[green]Bucket: [bold]{bucket}[/bold] has a bucket policy configured.[/green]")
        except Exception:
            rich_print(f"[yellow]Bucket: [bold]{bucket}[/bold] does not have a bucket policy configured.[/yellow]")

        try:
            bucket_acl = self.client.get_bucket_acl(Bucket=bucket)
            grants = bucket_acl.get('Grants', [])
            if any(grant['Grantee']['Type'] == 'Group' and 'AllUsers' in grant['Grantee']['URI'] for grant in grants):
                rich_print(f"[green]Bucket: [bold]{bucket}[/bold] has public access through ACL.[/green]")
            else:
                rich_print(f"[yellow]Bucket: [bold]{bucket}[/bold] does not have public access through ACL.[/yellow]")
        except Exception as e:
            rich_print(f"[yellow]Error checking ACL for bucket [bold]{bucket}[/bold]: {e}[/yellow]")

    def ensure_bucket_arn_in_iam_policy(self, bucket):
        """
        Ensure the Bucket ARN is used in an IAM policy to access the contents of the bucket (Do not use "*" principal).
        """
        bucket_arn = f"arn:aws:s3:::{bucket}"
        try:
            policy = self.client.get_bucket_policy(Bucket=bucket)['Policy']
            policy_statements = eval(policy).get('Statement', [])
            for statement in policy_statements:
                principal = statement.get('Principal', {})
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    rich_print(f"[yellow]Bucket: [bold]{bucket}[/bold] has a policy with a wildcard principal.[/yellow]")
                elif bucket_arn in statement.get('Resource', []):
                    rich_print(f"[green]Bucket: [bold]{bucket}[/bold] has a valid policy using its ARN.[/green]")
                else:
                    rich_print(f"[yellow]Bucket: [bold]{bucket}[/bold] does not have a valid policy using its ARN.[/yellow]")
        except Exception as e:
            rich_print(f"[yellow]Error checking policy for bucket [bold]{bucket}[/bold]: {e}[/yellow]")

    def ensure_lifecycle_policies(self, bucket):
        """
        Ensure that lifecycle policies have been configured to enforce business/regulatory requirements
        for data retention and disposal.
        """
        try:
            response = self.client.get_bucket_lifecycle_configuration(Bucket=bucket)
            rules = response.get('Rules', [])
            if rules:
                rich_print(f"[green]Bucket: [bold]{bucket}[/bold] has lifecycle policies configured.[/green]")
            else:
                rich_print(f"[yellow]Bucket: [bold]{bucket}[/bold] does not have any lifecycle policies configured.[/yellow]")
        except Exception as e:
            rich_print(f"[yellow]Error checking lifecycle policies for bucket [bold]{bucket}[/bold]: {e}[/yellow]")
