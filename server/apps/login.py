# 登录
from flask import jsonify, request

from apiflask import APIBlueprint
from apiflask.fields import String, Integer, Boolean
from uuid import uuid4
from model import User
from exts import db, login_manager
from flask_login import login_user, logout_user, login_required, current_user
bp = APIBlueprint("登录退出接口集合", __name__, url_prefix="/auth")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@bp.route('/register', methods=['POST'])
@bp.doc("系统用户创建接口", description="接收参数包括 新帐户名、新用户密码以及当前执行该注册操作的账户名")
@bp.input({
    "username": String(required=True),
    "password": String(required=True),
    "group": String(default="Normal")
})
@bp.output({
    "code": Integer(),
    "message": String()
})
@login_required
def register(json_data):
    data = json_data
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(user_name=username).first():
        return jsonify({
            'code': 400,
            'message': 'User already exists'}),

    user = User(
        user_id=str(uuid4()),
        user_name=data["username"],
        # created_by='Root',
        created_by=current_user.user_name,
        user_group='Normal'
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({
        'code': 201,
        'message': 'User registered successfully'})


@bp.route('/login', methods=['POST'])
@bp.doc("登录接口",
        description="输入用户名和密码，返回响应码code，消息message")
@bp.input({
    "username": String(required=True),
    "password": String(required=True)
})
@bp.output({
    "message": String()
})
def login(json_data):
    data = json_data
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(user_name=username).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({
            'code': 200,
            'message': 'Logged in successfully'})
    return jsonify({
        'code': 401,
        'message': 'Invalid credentials'})


@bp.route('/logout', methods=['POST'])
@bp.doc("登出接口",
        description="返回响应码code，消息message")
@bp.output({
    "message": String()
})
@login_required
def logout():
    logout_user()
    return jsonify({
        'code': 200,
        'message': 'Logged out successfully'})

@bp.route('/protected', methods=['GET'])
@bp.doc("登陆状态测试接口",
        description="返回响应码code，消息message")
@bp.output({
    "message": String()
})
@login_required
def protected():
    return jsonify({
        'code': 200,
        'message': f'Logged in as: {current_user.user_name}'})
