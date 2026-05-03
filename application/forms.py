
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, FieldList, FormField, BooleanField, RadioField, DateTimeField, DateField
from wtforms.validators import DataRequired, Email, Length, Optional
from flask_wtf.file import FileField, FileRequired, FileAllowed
from datetime import datetime

class LoginForm(FlaskForm):
    email = StringField('Email:', validators=[DataRequired(), Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField('Login')


class UserForm(FlaskForm):
    first_name = StringField('First Name:', validators=[DataRequired()])
    middle_name = StringField('Middle Name:', validators=[Optional()])
    last_name = StringField('Last Name:', validators=[DataRequired()])
    email = StringField('Email:', validators=[DataRequired(), Email()])
    role_id = SelectField('Role:', coerce=int, choices=[], validators=[DataRequired()])
    site_id = SelectField('Site:', coerce=int, choices=[], validators=[DataRequired()])
    rm_num = StringField('Room:', validators=[Optional()])
    status = SelectField('Status:',
        choices=[('Active', 'Active'), ('Inactive', 'Inactive')],
        validators=[DataRequired()]    )
    password = PasswordField('New Password:', validators=[Optional(), Length(min=10)])
    submit = SubmitField('Save User')


class RoleForm(FlaskForm):
    role_name = StringField('Role Name:', validators=[DataRequired()])
    submit = SubmitField('Save Role')


class SiteForm(FlaskForm):
    site_name = StringField('Site Name:', validators=[DataRequired()])
    site_acronyms = StringField('Site Acronym:', validators=[DataRequired()])
    site_code = StringField('Site Code:', validators=[DataRequired()])
    site_cds = StringField('CDS Code:', validators=[DataRequired()])
    site_address = StringField('Site Address:', validators=[DataRequired()])
    site_type = SelectField('Site Type:',
        choices=[('Elementary School', 'Elementary School'), ('Middle School', 'Middle School'), ('High School', 'High School'), ('District Office', 'District Office')],
        validators=[DataRequired()]    )
    submit = SubmitField('Save Site')


class NotificationForm(FlaskForm):
    msg_name = StringField('Message Name:', validators=[DataRequired()])
    msg_content = TextAreaField('Message:', validators=[DataRequired()])
    msg_status = RadioField('Status', choices=[('active', 'Active'), ('inactive', 'Inactive')], default='inactive', validators=[DataRequired()])
    submit = SubmitField('Save Notification Message')


class OrganizationForm(FlaskForm):
    organization_name = StringField('Organization Name', validators=[DataRequired()])
    site_version = StringField('Site Version', validators=[DataRequired()])
    submit = SubmitField('Save Settings')


class EmailConfigForm(FlaskForm):
    mail_server = StringField('SMTP Server', validators=[Optional()])
    mail_port = StringField('Port', validators=[Optional()])
    mail_use_tls = BooleanField('Use TLS')
    mail_use_ssl = BooleanField('Use SSL')
    mail_username = StringField('Username', validators=[Optional()])
    mail_password = PasswordField('Password', validators=[Optional()])
    mail_default_sender = StringField('Default Sender', validators=[Optional()])
    submit_email = SubmitField('Save Email Settings')



class PatronForm(FlaskForm):
    badge_id = StringField('Patron ID:', validators=[DataRequired()])
    first_name = StringField('First Name:', validators=[DataRequired()])
    middle_name = StringField('Middle Name:', validators=[Optional()])
    last_name = StringField('Last Name:', validators=[DataRequired()])
    email = StringField('Email:', validators=[DataRequired(), Email()])
    role_id = SelectField('Role:', coerce=int, choices=[], validators=[DataRequired()])
    site_id = SelectField('Site:', coerce=int, choices=[], validators=[DataRequired()])
    grade = SelectField('Grade', choices=[('KN', 'Kindergarten'),('1', '1st Grade'),('2', '2nd Grade'),
                                          ('3', '3rd Grade'),('4', '4th Grade'),('5', '5th Grade'),('6', '6th Grade'),
                                          ('7', '7th Grade'),('8', '8th Grade'),('9', '9th Grade'),('10', '10th Grade'),
                                          ('11', '11th Grade'),('12', '12th Grade')], validators=[DataRequired()])
    rm_num = StringField('Room:', validators=[Optional()])
    guardian_name = StringField('Name:', validators=[Optional()])
    phone = StringField('Phone Number:', validators=[Optional()])
    status = SelectField('Status:', choices=[('Active', 'Active'), ('Inactive', 'Inactive')], validators=[DataRequired()])
    submit = SubmitField('Save User')




class CategoryForm(FlaskForm):
    category_name = StringField('Category Name:', validators=[DataRequired()])
    submit = SubmitField('Save Category')   # changed label from 'Save Role'


class DeviceForm(FlaskForm):
    category_id = SelectField('Category', coerce=int, validators=[DataRequired()])
    serial_num = StringField('Serial Number', validators=[DataRequired(), Length(max=100)])
    device_tag = StringField('Device Tag', validators=[Optional(), Length(max=100)])
    brand_name = StringField('Brand Name', validators=[DataRequired(), Length(max=100)])
    model_name = StringField('Model Name', validators=[DataRequired(), Length(max=100)])
    # Loan status choices
    device_condition = SelectField('Device Condition', choices=[('new', 'New'),('good', 'Good'), 
                        ('broken_screen', 'Broken Screen'), ('damaged_keyboard', 'Damage Keyboard'), 
                        ('not_charging', 'Not Charging'),('water_damaged', 'Water Damaged'), ('lost', 'Lost Device')], validators=[DataRequired()])
    site_id = SelectField('Site', coerce=int, validators=[DataRequired()])
    assigned_to_id = SelectField('Assigned To', coerce=int, choices=[], validate_choice=False)
    return_at = DateField('Return Date', validators=[Optional()])
    chkout_at = DateField('Check Out Date', validators=[Optional()])
    comments = TextAreaField('Comments')
    in_repair = BooleanField('Currently Repairing')

    submit = SubmitField('Save Device')


