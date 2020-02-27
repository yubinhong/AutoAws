# AutoAws

### 1.环境
python 3.6.x python 3.7.x

django 3.0.3

sqlite 3.28(可以自行替换成mysql, mariadb)

### 2.安装
(1)安装依赖
<br>
pip3 install -r requirements.txt

(2)初始化数据库
<br>
python3 manage.py makemigrations 
<br>
python3 manage.py migrate

(3)启动
<br>
python3 manage.py runserver 0.0.0.0:8000
<br>
也可以做成gunicorn启动，自行百度解决，这边就不多说了。

