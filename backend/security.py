# coding=utf-8
from django.shortcuts import redirect


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
            return redirect('/login/')
    return wrapper

