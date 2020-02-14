import boto3


class AwsEc2(object):
    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key
        self.client = boto3.client(service_name='ec2', region_name="ap-northeast-1", aws_access_key_id=self.access_key,
                                   aws_secret_access_key=self.secret_key)

    def get_instance(self):
        res = self.client.describe_instances(MaxResults=100)
        return res


if __name__ == "__main__":
    ec2 = AwsEc2("xxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxx")
    res = ec2.get_instance()
    print(res)
