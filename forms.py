
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    SelectField,
    SubmitField,
)
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
)


class RegistrationForm(FlaskForm):
    name = StringField(
        "Full name",
        validators=[
            DataRequired(),
            Length(min=2, max=100),
        ],
    )

    email = StringField(
        "Email address",
        validators=[
            DataRequired(),
            Email(),
            Length(max=255),
        ],
    )

    role = SelectField(
        "Choose account role",
        choices=[
            ("viewer", "Viewer"),
            ("owner", "Document Owner"),
        ],
        validators=[DataRequired()],
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=12, max=128),
        ],
    )

    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )

    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField(
        "Email address",
        validators=[
            DataRequired(),
            Email(),
            Length(max=255),
        ],
    )

    password = PasswordField(
        "Password",
        validators=[DataRequired()],
    )

    submit = SubmitField("Log in")
