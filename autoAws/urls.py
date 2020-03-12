"""autoAws URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# from django.contrib import admin
from django.urls import path
from web import views
urlpatterns = [
    #    path('admin/', admin.site.urls),
    path('Login/', views.my_login),
    path('Logout/', views.my_logout),
    path('', views.index),
    path('AwsAccount/', views.aws_account),
    path('AwsAccountAdd/', views.aws_account_add),
    path('AwsAccountUpdate/', views.aws_account_update),
    path('AwsAccountDel/', views.aws_account_del),
    path('Template/', views.template),
    path('TemplateDetail/', views.template_detail),
    path('TemplateAdd/', views.template_add),
    path('TemplateDel/', views.template_del),
    path('TemplateUpdate/', views.template_update),
    path('Instance/', views.instance),
    path('InstanceAdd/', views.instance_add),
    path('InstanceDel/', views.instance_del),
    path('InstanceUpdate/', views.instance_update),
    path('Server/', views.server),
    path('ServerDeploy/', views.server_deploy),
    path('ServerAdd/', views.server_add),
    path('ServerUpdate/', views.server_update),
    path('Vpc/', views.vpc),
    path('Subnet/', views.subnet),
    path('AdminAccount/', views.admin_account),
    path('AdminAccountAdd/', views.admin_account_add),
    path('AdminAccountDel/', views.admin_account_del),
    path('AdminAccountUpdate/', views.admin_account_update),
    path('UserInfo/', views.user_info),
    path('Bucket/', views.bucket),
    path('BucketManage/', views.bucket_manage),
    path('Bind2faAuth/', views.bind_2fa_auth),
    path('Delete2faAuth/', views.delete_2fa_auth),
    path('CheckCode/', views.check_code),
    path('SecurityGroup/', views.security_group)

]
