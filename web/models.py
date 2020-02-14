from django.db import models


# Create your models here.
class Template(models.Model):
    name = models.CharField(max_length=64, verbose_name="模版名称", unique=True)
    create_time = models.DateTimeField(verbose_name="创建时间", auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "模版"
        verbose_name_plural = "模版"


class Instance(models.Model):
    name = models.CharField(max_length=128, verbose_name="实例名称")
    instance_type = models.CharField(max_length=32, verbose_name="实例类型")
    disk = models.CharField(max_length=8, verbose_name="硬盘大小")
    zone = models.CharField(max_length=32, verbose_name="区域")
    image_id = models.CharField(max_length=32, verbose_name="AMI")
    key_name = models.CharField(max_length=32, verbose_name="密钥对")
    security_ports = models.CharField(max_length=128, verbose_name="安全组端口")
    count = models.IntegerField(verbose_name="数量")
    template = models.ForeignKey("Template", on_delete=models.CASCADE)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "实例"
        verbose_name_plural = "实例"


class AwsAccount(models.Model):
    name = models.CharField(max_length=64, verbose_name="AWS账号名称", unique=True)
    access_key = models.CharField(max_length=64, verbose_name="公钥")
    secret_key = models.CharField(max_length=64, verbose_name="私钥")
    create_time = models.DateTimeField(verbose_name="创建时间", auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "AWS账号"
        verbose_name_plural = "AWS账号"

