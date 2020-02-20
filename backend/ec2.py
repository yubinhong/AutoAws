import boto3
import time

class AwsEc2(object):
    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key
        self.client = boto3.client(service_name='ec2', region_name="ap-northeast-1", aws_access_key_id=self.access_key,
                                   aws_secret_access_key=self.secret_key)
        self.resource = boto3.resource(service_name='ec2', region_name="ap-northeast-1", aws_access_key_id=self.access_key,
                                   aws_secret_access_key=self.secret_key)

    def get_instance(self, vpc_id):
        res = self.client.describe_instances(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [
                        vpc_id,
                    ]
                },
            ],
        )
        return res

    def get_vpc(self):
        res = self.client.describe_vpcs()
        return res

    def get_subnet(self, vpc_id):
        res = self.client.describe_subnets(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [
                        vpc_id,
                    ]
                },
            ]
        )
        return res

    def create_security_group(self, name, vpc_id):
        res = self.client.create_security_group(
            Description=name,
            GroupName=name,
            VpcId=vpc_id,
        )
        return res

    def create_instance_from_template(self, instance_template_list, vpc_id, subnet_id):
        res_list = []
        for instance_template in instance_template_list:
            res1 = self.create_security_group(instance_template['name'], vpc_id)
            res = self.resource.create_instances(
                BlockDeviceMappings=[
                    {
                        'DeviceName': '/dev/sda1',
                        'Ebs': {
                            'DeleteOnTermination': False,
                            'VolumeSize': instance_template['disk'],
                            'VolumeType': 'gp2',
                            'Encrypted': False
                        }
                    },
                ],
                ImageId=instance_template['image_id'],
                InstanceType=instance_template['instance_type'],
                KeyName=instance_template['key_name'],
                NetworkInterfaces=[
                    {
                        'AssociatePublicIpAddress': True,
                        'DeleteOnTermination': True,
                        'DeviceIndex': 0,
                        'Groups': [
                            res1['GroupId'],
                        ],
                        'SubnetId': subnet_id,
                        'InterfaceType': 'interface'
                    },
                ],
                MaxCount=1,
                MinCount=1,
            )
            instance = res[0]
            status = instance.state
            while status['Code'] != 16:
                time.sleep(10)
                instance.load()
                status = instance.state
            if status['Code'] == 16:
                instance.create_tags(
                    Tags=[{
                        'Key': 'Name',
                        'Value': instance_template['name']
                    }]
                )
            res_list.append(res[0])
        return res_list


if __name__ == "__main__":
    ec2 = AwsEc2("", "")
    instance_list = ec2.resource.instances.all()
    for instance in instance_list:
        print(instance.tags)

