from flask_wtf import Form
from wtforms import StringField, PasswordField,TextField
from wtforms.validators import DataRequired

class Login(Form):
    username = StringField('username',validators=[DataRequired()])
    password = PasswordField('passsword',validators=[DataRequired()])

class Register(Form):
	name = StringField('name',validators=[DataRequired()])
	username = StringField('username',validators=[DataRequired()])
	password = PasswordField('passsword',validators=[DataRequired()])
	mobile = TextField('mobile',validators=[DataRequired()])

