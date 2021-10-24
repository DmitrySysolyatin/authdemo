from typing import Optional
import hmac
import hashlib
import base64
import json

from fastapi import FastAPI, Cookie, Body
from fastapi.responses import Response


app = FastAPI()


SECRET_KEY = '99bd4bafdc3c7a824b592b0da11359c27c343fec722d99a669ff9c512b4654f9'
PASSWORD_SALT = '9be3113c9fb353434fa36cf857ec08fcd4350b086955cf854f45fc85d001b452'

users = {
    'mitya@user.com': {
        'name': 'Митя',
        'password': 'c41cdfa52713430e8407d0e3b9c678e8d4cd42a30c8a594643247e4f758c1de6',
        'balance': 1000
    },
    'dima@mail.ru': {
        'name': 'Дима',
        'password': 'f43a831ab1b9ab9e7b72e3f17b8f32a1a7246f191948ec3c3f28e93e41372fdf',
        'balance': 2000
    }
}

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    true_password_hash = users[username]['password'].lower()
    return password_hash == true_password_hash


def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_str(username_with_sign: str) -> Optional[str]:
    username_base64, sign = username_with_sign.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('../templates/index.html') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_str(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(f'Привет, {users[valid_username]["name"]}!<br>Ваш баланс: {users[valid_username]["balance"]}', media_type='text/html')


@app.post('/login')
def login_page(data: str = Body(...)):
    body = json.loads(data)
    username = body["username"]
    password = body["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                'success': False,
                'message': 'Я вас не знаю!'
            }),
            media_type='application/json')

    response = Response(
        json.dumps({
            'success': True,
            'message': f'Привет, {user["name"]}!<br>Ваш баланс: {user["balance"]}'
        }),
        media_type='application/json')

    encoded_username = base64.b64encode(username.encode()).decode()
    username_with_sign = f'{encoded_username}.{sign_data(username)}'
    response.set_cookie(key='username', value=username_with_sign)
    return response