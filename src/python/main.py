import sys
import boto3
from boto3 import client, Session
from botocore.exceptions import ProfileNotFound, ClientError

credentials_profile_name = "user"
role_arn = "arn:aws:iam::100000185324:role/user_role"
s3_url = "https://s3.wasabisys.com"
sts_url = "https://sts.wasabisys.com"


def load_access_keys():
    session = Session(profile_name=credentials_profile_name)
    credentials = session.get_credentials()
    return credentials.access_key, credentials.secret_key


def assume_role_with_policy():
    print("* Assume role with policy!")
    print("* Assume role!")
    print('*')
    sts_client = boto3.client('sts',
                              endpoint_url=sts_url,
                              aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)

    policy='''
       {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "s3:*",
              "Resource": ["*"]
            },
            {
              "Effect": "Deny",
              "Action": "s3:CreateBucket",
              "Resource": ["*"]
            }
          ]
        }
        '''

    session_token = sts_client.assume_role(DurationSeconds=900,
                                           RoleArn=role_arn,
                                           RoleSessionName='test-session',
                                           Policy=policy)

    temporary_access_key_id = session_token["Credentials"]["AccessKeyId"]
    temporary_secret_access_key = session_token["Credentials"]["SecretAccessKey"]
    temporary_session_token = session_token["Credentials"]["SessionToken"]

    print(f'* Loaded the following temporary credentials valid for 900 seconds after assuming role:')
    print(f'*    Access key ID: {temporary_access_key_id}')
    print(f'*    Secret Key   : {temporary_secret_access_key}')
    print(f'*    Session Token: {temporary_session_token}')
    print('*')
    print('* Creating S3 client using the temporary credentials for the assumed role')
    s3_client = boto3.client('s3',
                             endpoint_url=s3_url,
                             aws_access_key_id=temporary_access_key_id,
                             aws_secret_access_key=temporary_secret_access_key,
                             aws_session_token=temporary_session_token
                             )
    bucket_name = "test-bucket-sts"
    response = s3_client.list_objects(Bucket=bucket_name)
    print('* With these temporary credentials, we can list the bucket content but we are denied to create a new bucket with the provided policy')
    print(f'* The bucket {bucket_name} contains {len(response["Contents"])} objects')
    new_bucket_name="test-new-bucket-creation-with-assumed-role"
    try:
        response = s3_client.create_bucket(Bucket=new_bucket_name,
                                       CreateBucketConfiguration={'LocationConstraint': 'us-east-1'})
    except ClientError as error:
        print(f'* Error when trying to create a bucket: {error.response}')
    print('*')
    print('**************************************************************************')


def assume_role():
    print("* Assume role!")
    print('*')
    sts_client = boto3.client('sts',
                              endpoint_url=sts_url,
                              aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)

    session_token = sts_client.assume_role(DurationSeconds=900,
                                           RoleArn=role_arn,
                                           RoleSessionName='test-session')

    temporary_access_key_id = session_token["Credentials"]["AccessKeyId"]
    temporary_secret_access_key = session_token["Credentials"]["SecretAccessKey"]
    temporary_session_token = session_token["Credentials"]["SessionToken"]

    print(f'* Loaded the following temporary credentials valid for 900 seconds after assuming role:')
    print(f'*    Access key ID: {temporary_access_key_id}')
    print(f'*    Secret Key   : {temporary_secret_access_key}')
    print(f'*    Session Token: {temporary_session_token}')
    print('*')
    print('* Creating S3 client using the temporary credentials for the assumed role')
    s3_client = boto3.client('s3',
                             endpoint_url=s3_url,
                             aws_access_key_id=temporary_access_key_id,
                             aws_secret_access_key=temporary_secret_access_key,
                             aws_session_token=temporary_session_token
                             )
    bucket_name = "test-bucket-sts"
    response = s3_client.list_objects(Bucket=bucket_name)
    print(f'* The bucket {bucket_name} contains {len(response["Contents"])} objects')
    print('*')
    print('**************************************************************************')


def get_session_token():
    print("* Get session token!")
    print('*')
    sts_client = boto3.client('sts',
                              endpoint_url=sts_url,
                              aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)
    session_token = sts_client.get_session_token(DurationSeconds=900)
    temporary_access_key_id = session_token["Credentials"]["AccessKeyId"]
    temporary_secret_access_key = session_token["Credentials"]["SecretAccessKey"]
    temporary_session_token = session_token["Credentials"]["SessionToken"]

    print(f'* Loaded the following temporary credentials valid for 900 seconds:')
    print(f'*    Access key ID: {temporary_access_key_id}')
    print(f'*    Secret Key   : {temporary_secret_access_key}')
    print(f'*    Session Token: {temporary_session_token}')
    print('*')
    print('* Creating S3 client using the temporary credentials')
    s3_client = boto3.client('s3',
                             endpoint_url=s3_url,
                             aws_access_key_id=temporary_access_key_id,
                             aws_secret_access_key=temporary_secret_access_key,
                             aws_session_token=temporary_session_token
                             )
    bucket_name = "test-bucket-created-from-sts-credentials-python"
    response = s3_client.create_bucket(Bucket=bucket_name,
                                 CreateBucketConfiguration={'LocationConstraint': 'us-east-1'})
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        print(f'* Successfully created bucket "{bucket_name}" in us-east-1 region')
    print('*')
    print('**************************************************************************')


def get_caller_identity():
    sts_client = boto3.client('sts',
                                endpoint_url=sts_url,
                                aws_access_key_id=aws_access_key_id,
                                aws_secret_access_key=aws_secret_access_key)
    caller_identity = sts_client.get_caller_identity()
    print("* Get caller identity!")
    print('*')
    print(f'*     User id: {caller_identity["UserId"]}')
    print(f'*     Account: {caller_identity["Account"]}')
    print(f'*     ARN    : {caller_identity["Arn"]}')
    print('*')
    print('**************************************************************************')


def main():
    get_caller_identity()
    get_session_token()
    assume_role()
    assume_role_with_policy()
    return 0


if __name__ == '__main__':
    try:
        print('**************************************************************************')
        print('*                          AWS STS with Wasabi                           *')
        print('**************************************************************************')
        aws_access_key_id, aws_secret_access_key = load_access_keys()
        main()
    except ClientError as err:
        print(f'$ Error: {err.response}')