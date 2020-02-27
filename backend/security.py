# coding=utf-8
from django.shortcuts import redirect, render


def login_required(func):
    """

    :param func:
    """
    def wrapper(request):
        """

        :param request:
        :return:
        """
        if request.user.is_authenticated:
            return func(request)
        else:
            return redirect('/Login/')
    return wrapper


def user_is_superuser(func):
    """

    :param func:
    """
    def wrapper(request):
        """

        :param request:
        :return:
        """
        if request.user.is_superuser:
            return func(request)
        else:
            return render(request, 'X-admin/error.html')
    return wrapper
