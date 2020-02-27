import boto3
import time


class AwsS3(object):
    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key
        self.client = boto3.client(service_name='s3', region_name="ap-northeast-1", aws_access_key_id=self.access_key,
                                   aws_secret_access_key=self.secret_key)
        self.resource = boto3.resource(service_name='s3', region_name="ap-northeast-1",
                                       aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key)

    def get_buckets(self):
        return self.client.list_buckets()

    def bucket_add(self, name):
        return self.client.create_bucket(
            ACL='public-read',
            Bucket=name,
            CreateBucketConfiguration={
                'LocationConstraint': 'ap-northeast-1'
            }
        )

    def list_objects(self, bucket):
        return self.client.list_objects(Bucket=bucket)