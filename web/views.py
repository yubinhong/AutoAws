from django.shortcuts import render, redirect, HttpResponse
from backend.security import login_required
from backend.ec2 import AwsEc2
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from web import models
import json

# Create your views here.


def my_login(request):
    """
    :param request:
    """
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            result = {'status': 1, 'message': "登录成功"}
        else:
            result = {'status': 0, 'message': "用户名或密码错误"}
        return HttpResponse(json.dumps(result))

    else:
        if request.user.is_authenticated:
            return redirect("/")
        else:
            return render(request, "X-admin/login.html")


def my_logout(request):
    logout(request)
    return redirect("/Login/")


@login_required
def index(request):
    if request.method == 'GET':
        return render(request, 'X-admin/index.html')


@csrf_exempt
@xframe_options_exempt
@login_required
def aws_account(request):
    if request.method == 'GET':
        return render(request, 'X-admin/account-list.html')
    elif request.method == 'POST':
        page = int(request.POST.get('page',1))
        limit = int(request.POST.get('limit',10))
        count = models.AwsAccount.objects.all().count()
        data_list = models.AwsAccount.objects.all()[limit * (page - 1):limit * page]
        data_list = [{'id': data.pk, 'name': data.name, 'access_key': data.access_key, 'secret_key': data.secret_key,
                      'create_time': data.create_time.strftime("%Y-%m-%d %H:%M:%S")}
                     for data in data_list]
        result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def aws_account_add(request):
    if request.method == 'GET':
        return render(request, 'X-admin/account-add.html')
    elif request.method == 'POST':
        name = request.POST['name']
        access_key = request.POST['Access_Key']
        secret_key = request.POST['Secret_Key']
        try:
            models.AwsAccount(name=name, access_key=access_key, secret_key=secret_key).save()
            result = {'message': "添加成功！"}
        except Exception as e:
            result = {"message": "添加失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def aws_account_update(request):
    if request.method == 'POST':
        name = request.POST['name']
        rename = request.POST['rename']
        re_access_key = request.POST['access_key']
        re_secret_key = request.POST['secret_key']
        try:
            account_obj = models.AwsAccount.objects.get(name=name)
            account_obj.name = rename
            account_obj.access_key = re_access_key
            account_obj.secret_key = re_secret_key
            account_obj.save()
            result = {'message': "更新成功！", 'code': 0}
        except Exception as e:
            result = {"message": "更新失败！", 'code': 1}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def aws_account_del(request):
    if request.method == 'POST':
        name = request.POST['name']
        try:
            models.AwsAccount.objects.filter(name=name).delete()
            result = {'message': "删除成功！"}
        except Exception as e:
            result = {"message": "删除失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def template(request):
    if request.method == 'GET':
        return render(request, 'X-admin/template-list.html')
    elif request.method == 'POST':
        page = int(request.POST.get('page', 1))
        limit = int(request.POST.get('limit', 10))
        count = models.Template.objects.all().count()
        data_list = models.Template.objects.all()[limit * (page - 1):limit * page]
        data_list = [{'id': data.pk, 'name': data.name, 'create_time': data.create_time.strftime("%Y-%m-%d %H:%M:%S")}
                     for data in data_list]
        result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def template_detail(request):
    if request.method == 'GET':
        return render(request, 'X-admin/template-detail.html')


@csrf_exempt
@xframe_options_exempt
@login_required
def template_add(request):
    if request.method == 'GET':
        return render(request, 'X-admin/template-add.html')
    elif request.method == 'POST':
        name = request.POST['name']
        try:
            models.Template(name=name).save()
            result = {'message': "添加成功！"}
        except Exception as e:
            result = {"message": "添加失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def template_del(request):
    if request.method == 'POST':
        name = request.POST['name']
        try:
            models.Template.objects.filter(name=name).delete()
            result = {'message': "删除成功！"}
        except Exception as e:
            result = {"message": "删除失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@login_required
def template_update(request):
    if request.method == 'POST':
        name = request.POST['name']
        rename = request.POST['rename']
        try:
            tpl_obj = models.Template.objects.get(name=name)
            tpl_obj.name = rename
            tpl_obj.save()
            result = {'message': "更新成功！", 'code': 0}
        except Exception as e:
            result = {"message": "更新失败！", 'code': 1}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@login_required
def instance(request):
    if request.method == 'POST':
        page = int(request.POST.get('page', 1))
        limit = int(request.POST.get('limit', 10))
        template_name = request.POST['template']
        if template_name != '':
            tpl_obj = models.Template.objects.get(name=template_name)
            count = models.Instance.objects.filter(template=tpl_obj).count()
            data_list = models.Instance.objects.filter(template=tpl_obj)[limit * (page - 1):limit * page]

        else:
            count = models.Instance.objects.all().count()
            data_list = models.Instance.objects.all()[limit * (page - 1):limit * page]
        data_list = [{'id': data.pk, 'template_name': data.template.name, 'name': data.name,
                      'instance_type': data.instance_type, 'disk': data.disk, 'zone': data.zone,
                      'image_id': data.image_id, 'key_name': data.key_name, 'security_ports': data.security_ports,
                      'count': data.count} for data in data_list]
        result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def instance_add(request):
    if request.method == 'GET':
        return render(request, 'X-admin/instance-add.html')
    elif request.method == 'POST':
        template_name = request.POST['template_name']
        name = request.POST['name']
        instance_type = request.POST['instance_type']
        disk = request.POST['disk']
        zone = request.POST['zone']
        image_id = request.POST['image_id']
        key_name = request.POST['key_name']
        security_ports = request.POST['security_ports']
        count = request.POST['count']

        try:

            tpl_obj = models.Template.objects.get(name=template_name)
            models.Instance(name=name, instance_type=instance_type, disk=disk, zone=zone, image_id=image_id,
                            key_name=key_name, security_ports=security_ports, count=count, template=tpl_obj).save()
            result = {'message': "添加成功！", "code": 0}
        except Exception as e:
            result = {"message": "添加失败！", "code": 1}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@login_required
def instance_del(request):
    if request.method == 'POST':
        id = request.POST['id']
        try:
            models.Instance.objects.filter(pk=id).delete()
            result = {'message': "删除成功！"}
        except Exception as e:
            result = {"message": "删除失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@login_required
def instance_update(request):
    if request.method == 'POST':
        id = request.POST['id']
        re_name = request.POST['name']
        re_instance_type = request.POST['instance_type']
        re_disk = request.POST['disk']
        re_zone = request.POST['zone']
        re_image_id = request.POST['image_id']
        re_key_name = request.POST['key_name']
        re_security_ports = request.POST['security_ports']
        re_count = request.POST['count']
        try:
            in_obj = models.Instance.objects.get(pk=id)
            in_obj.name = re_name
            in_obj.instance_type = re_instance_type
            in_obj.disk = re_disk
            in_obj.zone = re_zone
            in_obj.image_id = re_image_id
            in_obj.key_name = re_key_name
            in_obj.security_ports = re_security_ports
            in_obj.count = re_count
            in_obj.save()
            result = {'message': "更新成功！", 'code': 0}
        except Exception as e:
            result = {"message": "更新失败！", 'code': 1}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def server(request):
    if request.method == 'GET':
        return render(request, 'X-admin/server-list.html')
    elif request.method == 'POST':
        page = int(request.POST.get('page', 1))
        limit = int(request.POST.get('limit', 10))
        account = request.POST['account']
        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsEc2(account_obj.access_key, account_obj.secret_key)
            res_dict = client.get_instance()
            count = len(res_dict['Reservations'])
            data_list = [{'vpc_id': data['Instances'][0]['VpcId'], 'name': data['Instances'][0]['Tags'][0]['Value'],
                          'instance_type': data['Instances'][0]['InstanceType'],
                          'zone': data['Instances'][0]['Placement']['AvailabilityZone'],
                          'image_id': data['Instances'][0]['ImageId'], 'key_name': data['Instances'][0]['KeyName'],
                          'security_group': ",".join([group['GroupName'] for group in data['Instances'][0]['SecurityGroups']]),
                          'private_address': data['Instances'][0]['PrivateIpAddress'],
                          'status': data['Instances'][0]['State']['Name']}
                         for data in res_dict['Reservations'][limit * (page - 1):limit * page]]
            result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        except Exception as e:
            print(e)
            result = {"code": '1', "msg": "获取失败！"}
        return HttpResponse(json.dumps(result))