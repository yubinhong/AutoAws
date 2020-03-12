import json

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, HttpResponse
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from django_google_auth2.google.bindgoogleauth.bindgoogleauth import bind_google_auth
from django_google_auth2.google.checkgoogleauth.checkgoogleauth import check_google_auth
from django_google_auth2.google.deletegoogleauth.deletegoogleauth import delete_google_auth
from django_google_auth2 import models as auth_models

from backend.ec2 import AwsEc2
from backend.s3 import AwsS3
from backend.security import login_required
from backend.security import user_is_superuser
from web import models


# Create your views here.


def my_login(request):
    """
    :param request:
    """
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        is_google_auth = len(auth_models.DjangoGoogleAuthenticator2.objects.filter(username=username))
        if user is not None:
            if is_google_auth:
                result = {'status': 2, 'message': '二次验证'}
            else:
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


@csrf_exempt
def check_code(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        code = request.POST['code']
        res = check_google_auth(username, code)
        if res['success']:
            login(request, user)
            result = {'message': "登录成功", 'status': 1}
        else:
            result = {'message': "验证码错误", 'status': 0}
        return HttpResponse(json.dumps(result))


def my_logout(request):
    logout(request)
    return redirect("/Login/")


@login_required
def index(request):
    if request.method == 'GET':
        username = request.user.username
        is_google_auth = len(auth_models.DjangoGoogleAuthenticator2.objects.filter(username=username))
        return render(request, 'X-admin/index.html', {'username': username, 'is_google_auth': is_google_auth})


@csrf_exempt
@xframe_options_exempt
@login_required
def aws_account(request):
    if request.method == 'GET':
        return render(request, 'X-admin/account-list.html')
    elif request.method == 'POST':
        page = int(request.POST.get('page', 1))
        limit = int(request.POST.get('limit', 10))
        count = models.AwsAccount.objects.all().count()
        data_list = models.AwsAccount.objects.all()[limit * (page - 1):limit * page]
        data_list = [{'id': data.pk, 'name': data.name, 'access_key': data.access_key,
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
                      'instance_type': data.instance_type, 'disk': data.disk, 'image_id': data.image_id,
                      'key_name': data.key_name, 'count': data.count}
                     for data in data_list]
        result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def instance_add(request):
    if request.method == 'GET':
        return render(request, 'X-admin/instance-add.html')
    elif request.method == 'POST':
        print(request.POST)
        template_name = request.POST['template_name']
        name = request.POST['name']
        instance_type = request.POST['instance_type']
        disk = int(request.POST['disk'])
        image_id = request.POST['image_id']
        key_name = request.POST['key_name']
        count = request.POST['count']

        try:
            tpl_obj = models.Template.objects.get(name=template_name)
            models.Instance(name=name, instance_type=instance_type, disk=disk, image_id=image_id,
                            key_name=key_name, count=count, template=tpl_obj).save()
            result = {'message': "添加成功！", "code": 0}
        except Exception as e:
            print(e)
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
        re_image_id = request.POST['image_id']
        re_disk = int(request.POST['disk'])
        re_key_name = request.POST['key_name']
        re_count = request.POST['count']
        try:
            in_obj = models.Instance.objects.get(pk=id)
            in_obj.name = re_name
            in_obj.instance_type = re_instance_type
            in_obj.disk = re_disk
            in_obj.image_id = re_image_id
            in_obj.key_name = re_key_name
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
        vpc_id = request.POST['vpc']
        servername = request.POST.get('servername', '')
        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsEc2(account_obj.access_key, account_obj.secret_key)
            if servername == '':
                res_list = client.get_instance_by_resource(vpc_id)
                count = len(res_list)
                data_list = [{'id': data.instance_id, 'name': data.tags[0]['Value'],
                              'instance_type': data.instance_type,
                              'zone': data.placement['AvailabilityZone'],
                              'image_id': data.image_id, 'key_name': data.key_name,
                              'security_group': ",".join([group['GroupName'] for group in data.security_groups]),
                              'private_address': data.private_ip_address if data.state['Name'] != 'terminated' else '',
                              'status': data.state['Name']}
                             for data in res_list[limit * (page - 1):limit * page]]
            else:
                res_dict = client.get_instance(vpc_id, servername)
                res_list = res_dict['Reservations']
                count = len(res_list)
                data_list = [{'id': data['Instances'][0]['InstanceId'], 'name': data['Instances'][0]['Tags'][0]['Value'],
                              'instance_type': data['Instances'][0]['InstanceType'],
                              'zone': data['Instances'][0]['Placement']['AvailabilityZone'],
                              'image_id': data['Instances'][0]['ImageId'], 'key_name': data['Instances'][0]['KeyName'],
                              'security_group': ",".join([group['GroupName'] for group in data['Instances'][0]['SecurityGroups']]),
                              'private_address': data['Instances'][0]['PrivateIpAddress'] if data['Instances'][0]['State']['Name'] != 'terminated' else '',
                              'status': data['Instances'][0]['State']['Name']}
                             for data in res_list[limit * (page - 1):limit * page]]
            result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        except Exception as e:
            print(e)
            result = {"code": '1', "msg": "获取失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def server_deploy(request):
    if request.method == 'GET':
        return render(request, 'X-admin/server-deploy.html')
    elif request.method == 'POST':
        template_id = request.POST['template']
        account = request.POST['account']
        vpc_id = request.POST['vpc']
        subnet_id = request.POST['subnet']
        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsEc2(account_obj.access_key, account_obj.secret_key)
            tpl_obj = models.Template.objects.get(pk=template_id)
            instance_list = models.Instance.objects.filter(template=tpl_obj)
            instance_list = [{'name': instance.name, 'disk': instance.disk, 'image_id': instance.image_id,
                              'instance_type': instance.instance_type, 'key_name': instance.key_name,
                              'count': instance.count}
                             for instance in instance_list]
            res_list = client.create_instance_from_template(instance_template_list=instance_list, vpc_id=vpc_id,
                                                            subnet_id=subnet_id)
            if len(res_list) > 0:
                result = {'code': 0, 'msg': "部署成功！"}
            else:
                result = {'code': 1, 'msg': "部署失败！"}
        except Exception as e:
            print(e)
            result = {'code': 1, 'msg': "部署失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def server_add(request):
    if request.method == 'POST':
        instance_dict = {}
        account = request.POST['account']
        vpc_id = request.POST['vpc']
        subnet_id = request.POST['subnet']
        instance_dict['name'] = request.POST['name']
        instance_dict['instance_type'] = request.POST['instance_type']
        instance_dict['disk'] = int(request.POST['disk'])
        instance_dict['image_id'] = request.POST['image_id']
        instance_dict['key_name'] = request.POST['key_name']
        instance_dict['count'] = int(request.POST['count'])
        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsEc2(account_obj.access_key, account_obj.secret_key)
            res = client.create_instance(instance_dict=instance_dict, vpc_id=vpc_id, subnet_id=subnet_id)
            if res['code'] == 0:
                result = {'code': 0, 'message': "添加成功！"}
            else:
                result = {'code': 1, 'message': res['msg']}
        except Exception as e:
            print(e)
            result = {'code': 1, 'msg': "添加失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@login_required
def server_update(request):
    if request.method == 'POST':
        account = request.POST['account']
        instance_id = request.POST['instance_id']
        security_group_list = request.POST['security_group_list']
        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsEc2(account_obj.access_key, account_obj.secret_key)
            res = client.modified_security_group(instance_id, security_group_list.split(","))
            if res['code'] == 0:
                result = {'code': 0, 'message': "更新成功！"}
            else:
                result = {'code': 1, 'message': res['msg']}
        except Exception as e:
            print(e)
            result = {'code': 1, 'msg': str(e)}
        return HttpResponse(json.dumps(result))

@csrf_exempt
@login_required
def vpc(request):
    if request.method == 'POST':
        account = request.POST['account']
        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsEc2(account_obj.access_key, account_obj.secret_key)
            res_dict = client.get_vpc()
            count = len(res_dict['Vpcs'])
            data_list = [{'vpc_id': data['VpcId'], 'name': data['Tags'][0]['Value'] if 'Tags' in data.keys() else data['VpcId']}
                         for data in res_dict['Vpcs']]
            result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        except Exception as e:
            print(e)
            result = {"code": '0', 'msg': 'success', 'count': 0, 'data': []}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@login_required
def subnet(request):
    if request.method == 'POST':
        account = request.POST['account']
        vpc_id = request.POST['vpc']
        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsEc2(account_obj.access_key, account_obj.secret_key)
            res_dict = client.get_subnet(vpc_id)
            count = len(res_dict['Subnets'])
            data_list = [{'subnet_id': data['SubnetId'], 'name': data['Tags'][0]['Value'] if 'Tags' in data.keys() else data['SubnetId'],
                          'cidr_block': data['CidrBlock'], 'avail_zone': data['AvailabilityZone']}
                         for data in res_dict['Subnets']]
            result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        except Exception as e:
            print(e)
            result = {"code": '0', 'msg': 'success', 'count': 0, 'data': []}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
@user_is_superuser
def admin_account(request):
    if request.method == 'GET':
        return render(request, 'X-admin/admin-list.html')
    elif request.method == 'POST':
        page = int(request.POST.get('page', 1))
        limit = int(request.POST.get('limit', 10))
        count = User.objects.all().count()
        user_list = User.objects.all()[limit * (page - 1):limit * page]
        user_list = [{'id': user.pk, 'username': user.username, 'email': user.email,
                      'create_time': user.date_joined.strftime("%Y-%m-%d %H:%M:%S"),
                      'is_superuser': user.is_superuser} for user in user_list]
        result = {'code': '0', 'msg': 'success', 'count': count, 'data': user_list}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
@user_is_superuser
def admin_account_add(request):
    if request.method == 'GET':
        return render(request, 'X-admin/admin-add.html')
    elif request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        passwd = request.POST['pass']
        is_superuser = int(request.POST['is_superuser'])
        try:
            if is_superuser:
                User.objects.create_superuser(username=username, email=email, password=passwd).save()
            else:
                User.objects.create_user(username=username, email=email, password=passwd).save()
            result = {'message': "添加成功！"}
        except Exception as e:
            result = {"message": "添加失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@login_required
@user_is_superuser
def admin_account_del(request):
    if request.method == 'POST':
        username = request.POST['username']
        try:
            User.objects.get(username=username).delete()
            result = {'message': "删除成功！"}
        except Exception as e:
            result = {"message": "删除失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@login_required
@user_is_superuser
def admin_account_update(request):
    if request.method == 'POST':
        username = request.POST['username']
        re_email = request.POST['email']
        re_pass = request.POST['pass']

        try:
            user_obj = User.objects.get(username=username)
            user_obj.email = re_email
            user_obj.set_password(re_pass)
            user_obj.save()
            result = {'message': "更新成功！", 'code': 0}
        except Exception as e:
            result = {"message": "更新失败！", 'code': 1}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def user_info(request):
    if request.method == 'GET':
        return render(request, 'X-admin/user-info.html', {'username': request.user.username, 'email': request.user.email})
    elif request.method == 'POST':
        re_email = request.POST['email']
        re_pass = request.POST['pass']
        try:
            request.user.email = re_email
            request.user.set_password(re_pass)
            request.user.save()
            result = {'message': "更新成功！", 'code': 0}
        except Exception as e:
            result = {"message": "更新失败！", 'code': 1}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def bucket(request):
    if request.method == 'GET':
        return render(request, 'X-admin/bucket-list.html')
    elif request.method == 'POST':
        page = int(request.POST.get('page', 1))
        limit = int(request.POST.get('limit', 10))
        account = request.POST['account']
        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsS3(account_obj.access_key, account_obj.secret_key)
            res_dict = client.get_buckets()
            res_list = res_dict['Buckets']
            count = len(res_list)
            data_list = [{'name': data['Name'], 'create_time': data['CreationDate'].strftime("%Y-%m-%d %H:%M:%S")}
                         for data in res_list[limit * (page - 1):limit * page]]
            result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        except Exception as e:
            print(e)
            result = {"code": '1', "msg": "获取失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def bucket_manage(request):
    if request.method == 'GET':
        return render(request, 'X-admin/bucket-manage.html')
    elif request.method == 'POST':
        page = int(request.POST.get('page', 1))
        limit = int(request.POST.get('limit', 10))
        account = request.POST['account']
        bucket = request.POST['bucket']
        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsS3(account_obj.access_key, account_obj.secret_key)
            res_dict = client.list_objects(bucket)
            res_list = res_dict['Contents']
            count = len(res_list)
            data_list = [{'object': data['Key'], 'last_modified': data['LastModified'].strftime("%Y-%m-%d %H:%M:%S"),
                          'size': data['Size']}
                         for data in res_list[limit * (page - 1):limit * page]]
            result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        except Exception as e:
            print(e)
            result = {"code": '1', "msg": "获取失败！"}
        return HttpResponse(json.dumps(result))


@csrf_exempt
@xframe_options_exempt
@login_required
def bind_2fa_auth(request):
    data = bind_google_auth(request.user.username)
    status = data["success"]
    if not status:
        return HttpResponse(data["data"])
    return render(request, 'X-admin/bind-google-auth.html', {"qr_code": data["data"]})


@csrf_exempt
@login_required
def delete_2fa_auth(request):
    if request.method == 'POST':
        username = request.POST.get('username', request.user.username)
        res = delete_google_auth(username)
        return HttpResponse(json.dumps(res))


@csrf_exempt
@xframe_options_exempt
@login_required
def security_group(request):
    if request.method == 'GET':
        return render(request, 'X-admin/security-group-list.html')
    elif request.method == 'POST':
        page = int(request.POST.get('page', 1))
        limit = int(request.POST.get('limit', 10))
        account = request.POST['account']
        groupname = request.POST.get('groupname', '')
        to_limit = int(request.POST.get('to_limit', 1))

        try:
            account_obj = models.AwsAccount.objects.get(name=account)
            client = AwsEc2(account_obj.access_key, account_obj.secret_key)
            if to_limit:
                res_dict = client.get_security_group()
                res_list = res_dict['SecurityGroups']
                count = len(res_list)
                data_list = [{'name': data['GroupName'], 'group_id': data['GroupId']}
                             for data in res_list[limit * (page - 1):limit * page]]
            else:
                param_dict = {'group-name': groupname, 'vpc-id': request.POST['vpc']}
                res_dict = client.get_security_group(**param_dict)
                res_list = res_dict['SecurityGroups']
                count = len(res_list)
                data_list = [{'name': data['GroupName'], 'group_id': data['GroupId']}
                             for data in res_list]
            result = {'code': '0', 'msg': 'success', 'count': count, 'data': data_list}
        except Exception as e:
            print(e)
            result = {"code": '1', "msg": "获取失败！"}
        return HttpResponse(json.dumps(result))
