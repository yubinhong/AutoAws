import boto3
import time


class AwsEc2(object):
    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key
        self.client = boto3.client(service_name='ec2', region_name="ap-northeast-1", aws_access_key_id=self.access_key,
                                   aws_secret_access_key=self.secret_key)
        self.resource = boto3.resource(service_name='ec2', region_name="ap-northeast-1",
                                       aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key)

    def get_instance(self, vpc_id, servername):
        res = self.client.describe_instances(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [
                        vpc_id,
                    ]
                },
                {
                    'Name': 'tag:Name',
                    'Values': [
                        servername
                    ]
                }
            ],
        )
        return res

    def get_instance_by_resource(self, vpc_id):
        instance_list = self.resource.instances.all()
        res_list = []
        for i in instance_list:
            if i.vpc_id == vpc_id:
                res_list.append(i)
        return res_list

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

    def get_security_group(self, name=''):
        if name != "":
            res = self.client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-name',
                        'Values': [
                            name,
                        ]
                    },
                ]
            )
        else:
            res = self.client.describe_security_groups()
        return res

    def create_security_group(self, name, vpc_id):
        res = self.client.create_security_group(
            Description=name,
            GroupName=name,
            VpcId=vpc_id,
        )
        return res

    def security_group(self, name, vpc_id):
        try:
            res = self.create_security_group(name, vpc_id)
            print(e)
        except Exception as e:
            res = self.get_security_group(name)['SecurityGroups'][0]

        return res

    def create_instance_from_template(self, instance_template_list, vpc_id, subnet_id):
        res_list = []
        for instance_template in instance_template_list:
            res1 = self.security_group(instance_template['name'], vpc_id)
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
                MaxCount=instance_template['count'],
                MinCount=instance_template['count'],
            )
            for instance in res:
                status = instance.state
                while status['Code'] != 16:
                    time.sleep(6)
                    instance.load()
                    status = instance.state
                if status['Code'] == 16:
                    instance.create_tags(
                        Tags=[{
                            'Key': 'Name',
                            'Value': instance_template['name']
                        }]
                    )
                res_list.append(instance)
        return res_list

    def create_instance(self, instance_dict, vpc_id, subnet_id):
        res1 = self.security_group(instance_dict['name'], vpc_id)
        try:
            res = self.resource.create_instances(
                BlockDeviceMappings=[
                    {
                        'DeviceName': '/dev/sda1',
                        'Ebs': {
                            'DeleteOnTermination': False,
                            'VolumeSize': instance_dict['disk'],
                            'VolumeType': 'gp2',
                            'Encrypted': False
                        }
                    },
                ],
                ImageId=instance_dict['image_id'],
                InstanceType=instance_dict['instance_type'],
                KeyName=instance_dict['key_name'],
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
                MaxCount=instance_dict['count'],
                MinCount=instance_dict['count'],
            )
        except Exception as e:
            result = {'code': 1, 'msg': str(e)}
            return result
        for instance in res:
            status = instance.state
            while status['Code'] != 16:
                time.sleep(6)
                instance.load()
                status = instance.state
            if status['Code'] == 16:
                instance.create_tags(
                    Tags=[{
                        'Key': 'Name',
                        'Value': instance_dict['name']
                    }]
                )
        result = {'code': 0}
        return result


if __name__ == "__main__":
    ec2 = AwsEc2("", "")
    res = ec2.get_instance_by_resource('xxxxxx')
    for i in res:
        print(i.placement)



