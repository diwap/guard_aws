from typing import Optional, List
from typer import Typer, Option
from typing_extensions import Annotated

from guard_aws.verify.s3 import CheckS3

app = Typer()

@app.command()
def check_s3(bucket: Annotated[Optional[List[str]], Option(help="[Optional] List of S3 buckets. eg: --bucket foo --bucket bar")] = None):
    buckets = []
    if bucket:
        buckets.extend(bucket)

    CheckS3(bucket).check()

@app.command()
def check_iam():
    print("Checking IAM permissions...")
