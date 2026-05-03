from flask import Blueprint, render_template, redirect, url_for, request, flash, abort, current_app, send_from_directory, jsonify, session
from flask_limiter.util import get_remote_address
from flask_login import login_user, login_required, logout_user, current_user
from flask_paginate import Pagination, get_page_args
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from .models import User, Role, Site, Notification, Organization, Device, Category, Patron, DeviceComment, BulkUploadLog, DeviceHistory
from .forms import LoginForm, UserForm, RoleForm, SiteForm, NotificationForm, OrganizationForm, EmailConfigForm, DeviceForm, CategoryForm, PatronForm
from .utils import validate_password, validate_file_upload, encrypt_mail_password, decrypt_mail_password, encrypt_field, decrypt_field, hash_email
from .email_utils import send_temp_password_email, send_password_updated_email
from main import db, login_manager, mail, limiter, scheduler, cache
from flask_mail import Message
from datetime import datetime, timedelta, timezone
import time, os, re, csv, logging, secrets, ftplib, io, socket
from sqlalchemy.sql import func
from sqlalchemy import case
from sqlalchemy.orm import joinedload


# Cached function to retrieve users with specific roles (1 and 2)
# This avoids repeated database queries for frequently accessed user data
@cache.cached(timeout=7200, key_prefix='assigned_users')
def get_assigned_users():
    """
    Retrieve all users with role IDs 1 or 2 from the database.
    Results are cached for 2 hours to improve performance.
    
    Returns:
        list: List of User objects with role_id 1 or 2
    """
    return User.query.filter(User.role_id.in_([1, 2])).all()


# Create a Blueprint for organizing routes
# This allows for modular application structure and route organization
routes_blueprint = Blueprint('routes', __name__)


@routes_blueprint.app_context_processor
def inject_active_notifications():
    try:
        notifications = Notification.query.filter_by(msg_status='Active').all()
    except Exception:
        notifications = []
    return dict(active_notifications=notifications)


# *****************************************************************
#-------------------- Core Setup -------------------------
# -------------- Do not change this section --------------
# *****************************************************************

# ****************** Force Password Change Enforcement *************
@routes_blueprint.before_request
def enforce_password_change():
    """Redirect users with a temporary password to the set-password page before they can do anything else."""
    if current_user.is_authenticated and getattr(current_user, 'must_change_password', False):
        allowed = {'routes.set_password', 'routes.logout', 'static'}
        if request.endpoint not in allowed:
            return redirect(url_for('routes.set_password'))



# ****************** Set Password (temp password flow) *************
@routes_blueprint.route('/set-password', methods=['GET', 'POST'])
@login_required
def set_password():
    org = db.session.get(Organization, 1)
    organization_name = org.organization_name if org else 'AssistITk12'

    if request.method == 'POST':
        new_password     = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not new_password or not confirm_password:
            flash('Both fields are required.', 'danger')
            return render_template('change_password.html', organization_name=organization_name)

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('change_password.html', organization_name=organization_name)

        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            flash(error_message, 'danger')
            return render_template('change_password.html', organization_name=organization_name)

        current_user.password_hash = generate_password_hash(new_password)
        current_user.must_change_password = False
        db.session.add(current_user)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"set_password commit failed for user {current_user.id}: {e}")
            flash('An error occurred while saving your password. Please try again.', 'danger')
            return render_template('change_password.html', organization_name=organization_name)
        flash('Password updated successfully. Welcome!', 'success')
        return redirect(url_for('routes.index'))

    return render_template('change_password.html', organization_name=organization_name)


# ****************** Login Setup *******************************
@login_manager.user_loader
def load_user(user_id):
    """
    Flask-Login user loader callback.
    Loads a user from the database for session management.
    
    Args:
        user_id (str): The user ID to load from database
        
    Returns:
        User: The User object for the specified ID
    """
    return db.session.get(User, int(user_id))

# ****************** Admin *******************************
def is_admin():
    """
    Check if the current user has admin privileges.
    Abort with 403 Forbidden if the user is not an admin.
    
    Assumes role_id 1 represents Admin status.
    """
    if not current_user.is_authenticated or current_user.role_id != 1:  # Assuming 1 = Admin
        abort(403)

def is_tech_role():
    """
    Check if the current user has a technical role.
    Abort with 403 Forbidden if the user is not in a tech role.
    
    Technical roles are Specialist (role_id=2) and Technician (role_id=3).
    """
    if not current_user.is_authenticated or current_user.role_id not in [2, 3]:  # Assuming 2 = Specialist, 3 = Technician
        abort(403)

# ****************** Forbidden Error Page *******************************
@routes_blueprint.app_errorhandler(403)
def forbidden_error(error):
    """
    Custom 403 error handler for the application.
    Renders a custom error page when access is forbidden.
    
    Args:
        error: The error that triggered this handler
        
    Returns:
        tuple: Rendered error template and 403 status code
    """
    return render_template('error.html'), 403


# ****************** Login Page *******************************
@routes_blueprint.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", key_func=get_remote_address)
def login():
    """
    Handle user login requests.
    
    GET: Display the login form
    POST: Process the login form submission
    
    Returns:
        Response: Rendered login template or redirect to index on successful login
    """
    # Fetch organization name for display on login page
    organization = db.session.get(Organization, 1)
    organization_name = organization.organization_name if organization else "TrackITk12"

    form = LoginForm()
    if form.validate_on_submit():
        key = current_app.config['SECRET_KEY']
        user = User.query.filter_by(email_hash=hash_email(form.email.data.strip(), key)).first()
        if user:
            if user.status != 'Active':
                flash('Login failed. Please check your credentials.', 'danger')
            elif user.failed_attempts >= 5:
                flash('Account locked due to too many failed login attempts. Please contact your administrator.', 'danger')
            elif check_password_hash(user.password_hash, form.password.data):
                # Regenerate session to prevent session fixation attacks
                session.clear()
                login_user(user)
                user.failed_attempts = 0
                db.session.commit()
                return redirect(url_for('routes.index'))
            else:
                user.failed_attempts += 1
                db.session.commit()
                flash('Login failed. Please check your credentials.', 'danger')
        else:
            flash('Login failed. Please check your credentials.', 'danger')

    return render_template(
        'login.html',
        form=form,
        organization_name=organization_name
    )


# ****************** Logout *******************************
@routes_blueprint.route('/logout')
@login_required
def logout():
    """
    Log out the currently authenticated user.
    Redirects to the login page after logout.
    
    Returns:
        Response: Redirect to login page
    """
    logout_user()
    # Clear session to prevent session fixation
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('routes.login'))


# ****************** Protected Attachment Download *******************************
@routes_blueprint.route('/uploads/attachments/<path:filename>')
@login_required
def serve_attachment(filename):
    """
    Serve uploaded attachment files only to authenticated users.
    Files are stored outside the static folder to prevent direct access.
    Admin and tech roles only.
    """
    if not (current_user.is_admin or current_user.is_tech_role):
        abort(403)
    upload_dir = current_app.config['UPLOAD_ATTACHMENT']
    return send_from_directory(upload_dir, filename)


# ****************** Change Password *******************************
@routes_blueprint.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """
    Handle password change requests securely.
    
    This function validates the current password, ensures the new password meets
    security requirements, and securely updates the password in the database.
    
    Returns:
        Response: JSON response indicating success or failure
    """
    try:
        # Extract form data
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Input validation
        if not all([current_password, new_password, confirm_password]):
            return jsonify({"success": False, "message": "All fields are required"}), 400
            
        # Verify new passwords match
        if new_password != confirm_password:
            return jsonify({"success": False, "message": "New passwords do not match"}), 400
        
        # Password complexity requirements
        if len(new_password) < 12:
            return jsonify({"success": False, "message": "Password must be at least 12 characters long"}), 400
            
        # Check for common password patterns using regex
        # This is a basic example - consider using a comprehensive password strength library
        if not (re.search(r'[A-Z]', new_password) and 
                re.search(r'[a-z]', new_password) and 
                re.search(r'[0-9]', new_password) and 
                re.search(r'[^A-Za-z0-9]', new_password)):
            return jsonify({
                "success": False, 
                "message": "Password must contain uppercase, lowercase, numbers, and special characters"
            }), 400
        
        # Get current user
        user = User.query.filter_by(id=current_user.id).first()
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
            
        # Verify current password is correct
        if not check_password_hash(user.password_hash, current_password):
            # Use consistent timing to prevent timing attacks
            from time import sleep
            sleep(0.5)  # Small delay to prevent rapid guessing
            return jsonify({"success": False, "message": "Current password is incorrect"}), 401
            
        # Hash the new password using werkzeug security functions
        password_hash = generate_password_hash(new_password, method='pbkdf2:sha256:150000')
        
        # Update the password in the database
        user.password_hash = password_hash
        
        # Add password change timestamp for auditing purposes
        user.password_changed_at = datetime.now(timezone.utc)
        
        # Commit the changes to the database
        db.session.commit()
        
        # Log the password change event (but not the password itself)
        current_app.logger.info(f"Password changed for user ID: {user.id}")
        
        # Optionally, update session to require re-login after password change
        # This depends on your security requirements
        # logout_user()
        
        return jsonify({"success": True, "message": "Password changed successfully"}), 200
        
    except Exception as e:
        # Roll back any database changes that might have occurred
        db.session.rollback()
        
        # Log the error, but don't expose details to the user
        current_app.logger.error(f"Password change error: {str(e)}")
        
        # Generic error message to avoid exposing system details
        return jsonify({"success": False, "message": "An error occurred. Please try again later."}), 500




@routes_blueprint.route('/organization', methods=['GET', 'POST'])
@login_required
def organization():
    is_admin()
    # Map URL paths to readable page names for navigation
    page_names = {'/organization': 'Data Integration'}
    # Get current path for navigation highlighting
    current_path = request.path
    # Get page name for display in UI
    current_page_name = page_names.get(current_path, 'Unknown Page')
    
    # Hardcoding organization_id to 1
    # NOTE: This assumes a single organization in the system
    organization_id = 1
    organization = db.get_or_404(Organization, organization_id)
    
    # Initialize form with current organization data
    form = OrganizationForm(obj=organization)
    email_form = EmailConfigForm(obj=organization)

    if form.validate_on_submit():
        # Check for duplicate organization names (excluding the current one)
        existing_organization = Organization.query.filter(
            Organization.organization_name == form.organization_name.data,
            Organization.id != organization.id
        ).first()


        # Update organization with form data
        organization.organization_name = form.organization_name.data
        organization.site_version = form.site_version.data
        db.session.commit()  # Save changes to database

        flash('Organization updated successfully!', 'success')
        return redirect(url_for('routes.organization'))

    # For GET requests or invalid form submissions, display the form
    return render_template('organization.html',
                          form=form,
                          email_form=email_form,
                          organization=organization,
                          current_path=current_path,
                          current_page_name=current_page_name)

# *****************************************************************
#-------------------- END Core Setup ---------------------
# -------------- Do not change this section --------------
# *****************************************************************

# ****************** Email Configuration *******************************
@routes_blueprint.route('/email-config', methods=['POST'])
@login_required
def email_config():
    """
    Save Flask-Mail SMTP configuration from the organization settings page.
    Updates the Organization record and immediately applies settings to the running app.
    """
    is_admin()
    organization = db.get_or_404(Organization, 1)
    email_form = EmailConfigForm()

    if email_form.validate_on_submit():
        organization.mail_server = email_form.mail_server.data or None
        organization.mail_port = email_form.mail_port.data or None
        organization.mail_use_tls = email_form.mail_use_tls.data
        organization.mail_use_ssl = email_form.mail_use_ssl.data
        organization.mail_username = email_form.mail_username.data or None
        if email_form.mail_password.data:
            organization.mail_password = encrypt_mail_password(
                email_form.mail_password.data, current_app.config['SECRET_KEY']
            )
        organization.mail_default_sender = email_form.mail_default_sender.data or None
        db.session.commit()

        # Apply updated settings to the running Flask-Mail instance
        current_app.config['MAIL_SERVER'] = organization.mail_server or 'localhost'
        current_app.config['MAIL_PORT'] = organization.mail_port or 587
        current_app.config['MAIL_USE_TLS'] = bool(organization.mail_use_tls)
        current_app.config['MAIL_USE_SSL'] = bool(organization.mail_use_ssl)
        current_app.config['MAIL_USERNAME'] = organization.mail_username
        current_app.config['MAIL_PASSWORD'] = decrypt_mail_password(
            organization.mail_password or '', current_app.config['SECRET_KEY']
        )
        current_app.config['MAIL_DEFAULT_SENDER'] = organization.mail_default_sender
        mail.init_app(current_app)

        flash('Email settings updated successfully!', 'success')
    else:
        for field, errors in email_form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'danger')

    return redirect(url_for('routes.organization'))


# ****************** Test Email *******************************
@routes_blueprint.route('/email-config/test', methods=['POST'])
@login_required
def test_email():
    """
    Send a test email to verify the current Flask-Mail configuration.
    Returns JSON with success/error details.
    """
    is_admin()
    recipient = request.form.get('test_recipient', '').strip()
    if not recipient:
        return jsonify({'success': False, 'message': 'Recipient email is required.'}), 400

    if not current_app.config.get('MAIL_SERVER'):
        return jsonify({'success': False, 'message': 'No SMTP server configured. Save your Email Configuration settings first.'}), 400

    try:
        msg = Message(
            subject='Test Email – TrackITK12',
            recipients=[recipient],
            body=(
                'This is a test email sent from TrackITK12.\n\n'
                'Your email configuration is working correctly.\n\n'
                '— TrackITK12 System'
            )
        )
        mail.send(msg)
        current_app.logger.info(f"Test email sent to {recipient} by user {current_user.id}")
        return jsonify({'success': True, 'message': f'Test email sent to {recipient}.'})
    except ConnectionRefusedError:
        current_app.logger.error(f"Test email failed: connection refused to {current_app.config.get('MAIL_SERVER')}:{current_app.config.get('MAIL_PORT')}")
        return jsonify({'success': False, 'message': f"Connection refused. Check that your SMTP server ({current_app.config.get('MAIL_SERVER')}:{current_app.config.get('MAIL_PORT')}) is correct and reachable."}), 500
    except Exception as e:
        current_app.logger.error(f"Test email failed: {type(e).__name__}: {e}")
        return jsonify({'success': False, 'message': 'Failed to send test email. Check your SMTP settings and server logs.'}), 500


# *****************************************************************
#-------------------- Site Template Pages ---------------------
# *****************************************************************

# *********************************************************************
# ****************** Dashboard Page *******************************
@routes_blueprint.route('/', methods=['GET', 'POST'])
@login_required
def index():
    # Filter options for dropdowns
    sites = Site.query.order_by(Site.site_name).all()
    roles = Role.query.order_by(Role.role_name).all()
    categories = Category.query.order_by(Category.category_name).all()
    grades = [r[0] for r in db.session.query(Patron.grade).distinct().order_by(Patron.grade).all()]

    # Active filter values — default site to current user's site unless admin
    default_site = '' if current_user.is_admin else str(current_user.site_id)
    site_filter = request.args.get('site_filter', default_site)
    grade_filter = request.args.get('grade_filter', '')
    role_filter = request.args.get('role_filter', '')
    category_filter = request.args.get('category_filter', '')

    # Build base filtered device query
    base_q = Device.query
    if site_filter:
        base_q = base_q.filter(Device.site_id == int(site_filter))
    if category_filter:
        base_q = base_q.filter(Device.category_id == int(category_filter))
    if grade_filter or role_filter:
        base_q = base_q.join(Patron, Device.assigned_to_id == Patron.id)
        if grade_filter:
            base_q = base_q.filter(Patron.grade == grade_filter)
        if role_filter:
            base_q = base_q.filter(Patron.role_id == int(role_filter))

    # Stat card counts using filtered base
    total_devices = base_q.count()
    checked_out = base_q.filter(Device.assigned_to_id != None, Device.return_at == None).count()
    available = base_q.filter(db.or_(Device.assigned_to_id == None, Device.return_at != None)).count()
    in_repair = base_q.filter(Device.in_repair == True).count()

    # Category stats with filters applied
    cat_q = db.session.query(
        Category.id,
        Category.category_name,
        db.func.count(Device.id)
    ).join(Device, Device.category_id == Category.id)
    if site_filter:
        cat_q = cat_q.filter(Device.site_id == int(site_filter))
    if category_filter:
        cat_q = cat_q.filter(Device.category_id == int(category_filter))
    if grade_filter or role_filter:
        cat_q = cat_q.join(Patron, Device.assigned_to_id == Patron.id)
        if grade_filter:
            cat_q = cat_q.filter(Patron.grade == grade_filter)
        if role_filter:
            cat_q = cat_q.filter(Patron.role_id == int(role_filter))
    category_stats = cat_q.group_by(Category.id, Category.category_name).order_by(db.func.count(Device.id).desc()).all()

    # In-repair devices with filters applied
    repair_query = base_q.filter(Device.in_repair == True)
    repair_devices = repair_query.order_by(Device.repair_date.asc()).all()
    today = datetime.now(timezone.utc).date()

    return render_template(
        'index.html',
        total_devices=total_devices,
        checked_out=checked_out,
        available=available,
        in_repair=in_repair,
        category_stats=category_stats,
        repair_devices=repair_devices,
        today=today,
        sites=sites,
        roles=roles,
        categories=categories,
        grades=grades,
        site_filter=site_filter,
        grade_filter=grade_filter,
        role_filter=role_filter,
        category_filter=category_filter,
        current_page_name='Dashboard',
    )




# ***************************************************************
# ****************** Profile Page *******************************
@routes_blueprint.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
        # Mapping paths to page names
    page_names = {'/profile': 'My Profile'}
    # Get the current path
    current_path = request.path
    # Get the corresponding page name or default to "Unknown Page"
    current_page_name = page_names.get(current_path, 'Unknown Page')
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        # Validate passwords
        if not current_password or not password or not confirm_password:
            flash('All password fields are required.', 'danger')
        elif not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect.', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
        else:
            # Validate password complexity
            is_valid, error_message = validate_password(password)
            if not is_valid:
                flash(error_message, 'danger')
                return render_template('profile.html', user=current_user, role=current_user.role,
                    current_path=current_path, current_page_name=current_page_name)

            # Password is valid, proceed with update
            # Update password and save user
            current_user.password_hash = generate_password_hash(password)
            current_user.must_change_password = False
            try:
                db.session.commit()
                flash('Password updated successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"profile password update failed for user {current_user.id}: {e}")
                flash('An error occurred while updating your password. Please try again.', 'danger')
            return redirect(url_for('routes.profile'))
    role = current_user.role  # Assuming current_user has a 'role' attribute
    return render_template('profile.html', user=current_user, role=role,
        current_path=current_path, 
        current_page_name=current_page_name
    )



# *********************************************************************
# ****************** Users Management Page ****************************
@routes_blueprint.route('/users', methods=['GET'])
@login_required
def users():
    page_names = {'/users': 'Manage Users'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    
    if not (current_user.is_admin or current_user.is_tech_role):
        abort(403)

    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    search = request.args.get('search', '').strip()
    site_filter = request.args.get('site_filter', '').strip()
    role_filter = request.args.get('role_filter', '').strip()
    query = User.query
    # Apply search filter
    if search:
        query = query.filter(
            db.or_(
                User.first_name.ilike(f"%{search}%"),
                User.last_name.ilike(f"%{search}%"),
            )
        )
    # Apply site filter
    if site_filter:
        query = query.filter(User.site_id == site_filter)
    # Apply role filter
    if role_filter:
        query = query.filter(User.role_id == role_filter)
    total = query.count()
    users = query.order_by(User.first_name.asc()).offset(offset).limit(per_page).all()
    # Fetch all sites and roles for the filter dropdowns
    sites = Site.query.order_by(Site.site_name.asc()).all()
    roles = Role.query.order_by(Role.role_name.asc()).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template(
        'users.html',
        users=users,
        pagination=pagination,
        per_page=per_page,
        total=total,
        current_path=current_path,
        current_page_name=current_page_name,
        sites=sites,
        roles=roles,
        search=search,
        site_filter=site_filter,
        role_filter=role_filter
    )


# ****************** Add User Page *******************************
@routes_blueprint.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    is_admin()  # Ensure only admins can access this route
    # Mapping paths to page names
    page_names = {'/add_user': 'Add User'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')

    form = UserForm()
    form.role_id.choices = [(role.id, role.role_name) for role in Role.query.all()]
    form.site_id.choices = [(site.id, site.site_name) for site in Site.query.all()]
    if form.validate_on_submit():
        # Check if a user with the same email already exists
        key = current_app.config['SECRET_KEY']
        existing_user = User.query.filter_by(email_hash=hash_email(form.email.data.strip(), key)).first()
        if existing_user:
            flash('A user with this email already exists. Please use a different email.', 'danger')
            return render_template('add_user.html', form=form)
        # Validate password complexity
        password = form.password.data
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message, 'danger')
            return render_template('add_user.html', form=form)
        # Proceed with creating the new user
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            first_name=form.first_name.data,
            middle_name=form.middle_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            status=form.status.data,
            rm_num=form.rm_num.data,
            site_id=form.site_id.data,
            role_id=form.role_id.data,
            password_hash=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('routes.users'))
    return render_template('add_user.html', form=form,current_path=current_path,
        current_page_name=current_page_name)




# ****************** Edit User Page *******************************
# ****************** Send Temporary Password (AJAX) *******************************
@routes_blueprint.route('/send_temp_password/<int:user_id>', methods=['POST'])
@login_required
def send_temp_password(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    user = db.get_or_404(User, user_id)
    temp_password = secrets.token_urlsafe(12)

    try:
        send_temp_password_email(user, temp_password)
    except Exception as e:
        current_app.logger.error(f"send_temp_password failed for user {user_id}: {type(e).__name__}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Failed to send the temporary password email. Check your SMTP configuration.'}), 500

    user.password_hash = generate_password_hash(temp_password)
    user.must_change_password = True
    db.session.commit()

    return jsonify({'success': True, 'message': f'Temporary password sent to {user.email}'})



@routes_blueprint.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not (current_user.is_admin or current_user.is_tech_role):
        abort(403)
    user = db.get_or_404(User, user_id)
    form = UserForm(obj=user)
    # Populate dynamic choices for role_id and site_id
    form.role_id.choices = [(role.id, role.role_name) for role in Role.query.all()]
    form.site_id.choices = [(site.id, site.site_name) for site in Site.query.all()]
    if form.validate_on_submit():
        # Check if a user with the same email already exists
        key = current_app.config['SECRET_KEY']
        existing_user = User.query.filter(User.email_hash == hash_email(form.email.data.strip(), key), User.id != user.id).first()
        if existing_user:
            flash('A user with this email already exists. Please use a different email.', 'danger')
            return render_template('edit_user.html', form=form, user=user)
        # Track changes to avoid unnecessary updates
        changes_made = False
        # Update user details only if there are changes
        if user.first_name != form.first_name.data:
            user.first_name = form.first_name.data
            changes_made = True
        if user.middle_name != form.middle_name.data:
            user.middle_name = form.middle_name.data
            changes_made = True
        if user.last_name != form.last_name.data:
            user.last_name = form.last_name.data
            changes_made = True
        if user.email != form.email.data:
            user.email = form.email.data
            changes_made = True
        if user.status != form.status.data:
            user.status = form.status.data
            if form.status.data == 'Active':
                user.failed_attempts = 0
            changes_made = True
        if user.rm_num != form.rm_num.data:
            user.rm_num = form.rm_num.data
            changes_made = True
        if user.site_id != form.site_id.data:
            user.site_id = form.site_id.data
            changes_made = True
        if user.role_id != form.role_id.data:
            user.role_id = form.role_id.data
            changes_made = True
        # Validate and update password only if provided
        password_changed = False
        if form.password.data:
            password = form.password.data
            is_valid, error_message = validate_password(password)
            if not is_valid:
                flash(error_message, 'danger')
                return render_template('edit_user.html', form=form, user=user)
            user.password_hash = generate_password_hash(password)
            user.must_change_password = False
            changes_made = True
            password_changed = True
        # Commit changes only if any were made
        if changes_made:
            db.session.commit()
            if password_changed:
                send_password_updated_email(user)
            flash('User updated successfully!', 'success')
            return redirect(url_for('routes.users'))
        else:
            flash('No changes were made.', 'info')
    return render_template('edit_user.html', form=form, user=user)



# ****************** Delete User Page *******************************
@routes_blueprint.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
# @csrf.exempt  # Optional: Exempt from CSRF if needed
def delete_user(user_id):
    is_admin()  # Ensure only admins can access this route
    user = db.get_or_404(User, user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'warning')
    return redirect(url_for('routes.users'))



SITE_REQUIRED = ['site_name', 'site_acronyms', 'site_cds', 'site_code', 'site_address', 'site_type']


# ****************** Upload Users Page *******************************
@routes_blueprint.route('/bulk-data-upload', methods=['GET'])
@login_required
def upload_users():
    is_admin()
    log_page  = request.args.get('log_page', 1, type=int)
    per_page  = 10
    user_logs = (
        BulkUploadLog.query
        .options(joinedload(BulkUploadLog.uploader))
        .order_by(BulkUploadLog.uploaded_at.desc())
        .paginate(page=log_page, per_page=per_page, error_out=False)
    )
    org  = db.session.get(Organization, 1)
    ftp_host_plain     = ''
    ftp_username_plain = ''
    schedule_time = ''
    if org:
        key = current_app.config['SECRET_KEY']
        ftp_host_plain     = decrypt_mail_password(org.ftp_host_enc or '', key)
        ftp_username_plain = decrypt_mail_password(org.ftp_username_enc or '', key)
        if org.ftp_schedule_hour is not None:
            schedule_time = f"{org.ftp_schedule_hour:02d}:{org.ftp_schedule_minute or 0:02d}"
    schedule_start_date = org.ftp_schedule_start_date.isoformat() if org and org.ftp_schedule_start_date else ''
    schedule_stop_date  = org.ftp_schedule_stop_date.isoformat()  if org and org.ftp_schedule_stop_date  else ''
    return render_template('bulk_upload_data.html',
                           user_logs=user_logs,
                           org=org,
                           ftp_host_plain=ftp_host_plain,
                           ftp_username_plain=ftp_username_plain,
                           ftp_schedule_time=schedule_time,
                           ftp_schedule_start_date=schedule_start_date,
                           ftp_schedule_stop_date=schedule_stop_date,
                           current_page_name='Bulk Upload Users')


def _find_site(name):
    """Look up a site by name, case-insensitively, after stripping whitespace."""
    name = name.strip()
    return (
        Site.query.filter_by(site_name=name).first() or
        Site.query.filter(func.lower(Site.site_name) == name.lower()).first()
    )


def _process_sites_rows(rows):
    """Upsert sites from a list of CSV row dicts. Returns (added, updated)."""
    added = updated = 0
    required = ['site_name', 'site_code', 'site_cds', 'site_acronyms', 'site_address', 'site_type']
    for row in rows:
        missing = [f for f in required if not row.get(f)]
        if missing:
            raise ValueError(f"Row missing required fields: {', '.join(missing)}")
        site = (
            Site.query.filter_by(site_name=row['site_name'].strip()).first() or
            Site.query.filter_by(site_acronyms=row['site_acronyms'].strip()).first() or
            Site.query.filter_by(site_code=row['site_code'].strip()).first()
        )
        if site:
            site.site_name     = row['site_name'].strip()
            site.site_code     = row['site_code'].strip()
            site.site_cds      = row['site_cds'].strip()
            site.site_acronyms = row['site_acronyms'].strip()
            site.site_address  = row['site_address'].strip()
            site.site_type     = row['site_type'].strip()
            updated += 1
        else:
            db.session.add(Site(
                site_name     = row['site_name'].strip(),
                site_code     = row['site_code'].strip(),
                site_cds      = row['site_cds'].strip(),
                site_acronyms = row['site_acronyms'].strip(),
                site_address  = row['site_address'].strip(),
                site_type     = row['site_type'].strip(),
            ))
            added += 1
    return added, updated


def _process_patrons_rows(rows):
    """Upsert patrons from a list of CSV row dicts. Returns (added, updated)."""
    added = updated = 0
    required = ['badge_id', 'first_name', 'last_name', 'email', 'grade', 'status', 'rm_num', 'role_name', 'site_name']
    for i, row in enumerate(rows, 1):
        missing = [f for f in required if not row.get(f)]
        if missing:
            raise ValueError(f"Row {i}: missing required fields: {', '.join(missing)}")
        role = Role.query.filter_by(role_name=row['role_name'].strip()).first()
        if not role:
            raise ValueError(f"Row {i}: role '{row['role_name']}' not found.")
        site = _find_site(row['site_name'])
        if not site:
            raise ValueError(f"Row {i}: site '{row['site_name'].strip()}' not found.")
        patron = Patron.query.filter_by(badge_id=row['badge_id'].strip()).first()
        if patron:
            patron.first_name    = row['first_name'].strip()
            patron.middle_name   = row.get('middle_name', '').strip() or None
            patron.last_name     = row['last_name'].strip()
            patron.email         = row['email'].strip()
            patron.grade         = row['grade'].strip()
            patron.status        = row['status'].strip()
            patron.rm_num        = row['rm_num'].strip()
            patron.guardian_name = row.get('guardian_name', '').strip() or None
            patron.phone         = row.get('phone', '').strip() or None
            patron.role_id       = role.id
            patron.site_id       = site.id
            updated += 1
        else:
            db.session.add(Patron(
                badge_id     = row['badge_id'].strip(),
                first_name   = row['first_name'].strip(),
                middle_name  = row.get('middle_name', '').strip() or None,
                last_name    = row['last_name'].strip(),
                email        = row['email'].strip(),
                grade        = row['grade'].strip(),
                status       = row['status'].strip(),
                rm_num       = row['rm_num'].strip(),
                guardian_name= row.get('guardian_name', '').strip() or None,
                phone        = row.get('phone', '').strip() or None,
                role_id      = role.id,
                site_id      = site.id,
            ))
            added += 1
    return added, updated


# ****************** Import Bulk Users *******************************
@routes_blueprint.route('/bulk-upload-users', methods=['POST'])
@login_required
def bulk_upload_users():
    is_admin()

    files = request.files.getlist('csvFile')
    files = [f for f in files if f and f.filename]
    if not files:
        flash('No file selected.', 'danger')
        return redirect(url_for('routes.upload_users'))

    for f in files:
        if not f.filename.lower().endswith('.csv'):
            flash(f'Invalid file: {f.filename}. Only .csv files are accepted.', 'danger')
            return redirect(url_for('routes.upload_users'))

    # Process order: sites first, then users, then patrons
    def _file_order(f):
        n = f.filename.lower()
        if n == 'sites.csv': return 0
        if n == 'patrons.csv': return 2
        return 1
    files.sort(key=_file_order)

    flash_messages = []

    for file in files:
        filename = secure_filename(file.filename)
        is_sites   = filename.lower() == 'sites.csv'
        is_patrons = filename.lower() == 'patrons.csv'
        added = updated = total = 0

        try:
            stream = file.stream.read().decode('UTF-8')
            rows = list(csv.DictReader(stream.splitlines()))
            total = len(rows)

            if is_sites:
                added, updated = _process_sites_rows(rows)
                db.session.commit()
                db.session.add(BulkUploadLog(
                    filename=f'[Sites] {filename}',
                    uploaded_by_id=current_user.id,
                    total_records=total,
                    users_added=added,
                    users_updated=updated,
                    status='success'
                ))
                db.session.commit()
                flash_messages.append(f'Sites: {added} added, {updated} updated.')

            elif is_patrons:
                required_cols = ['badge_id', 'first_name', 'last_name', 'email', 'grade', 'status', 'rm_num', 'role_name', 'site_name']
                row_errors = []
                for i, row in enumerate(rows, start=2):
                    missing = [c for c in required_cols if not row.get(c, '').strip()]
                    if missing:
                        row_errors.append(f"Row {i}: missing {', '.join(missing)}")
                        continue
                    role = Role.query.filter(db.func.lower(Role.role_name) == row['role_name'].strip().lower()).first()
                    site = Site.query.filter(db.func.lower(Site.site_name) == row['site_name'].strip().lower()).first()
                    if not role:
                        row_errors.append(f"Row {i}: role '{row['role_name']}' not found.")
                        continue
                    if not site:
                        row_errors.append(f"Row {i}: site '{row['site_name']}' not found.")
                        continue
                    patron = Patron.query.filter_by(badge_id=row['badge_id'].strip()).first()
                    if patron:
                        patron.first_name    = row['first_name'].strip()
                        patron.middle_name   = row.get('middle_name', '').strip() or None
                        patron.last_name     = row['last_name'].strip()
                        patron.email         = row['email'].strip()
                        patron.grade         = row['grade'].strip()
                        patron.status        = row['status'].strip()
                        patron.rm_num        = row['rm_num'].strip()
                        patron.guardian_name = row.get('guardian_name', '').strip() or None
                        patron.phone         = row.get('phone', '').strip() or None
                        patron.role_id       = role.id
                        patron.site_id       = site.id
                        updated += 1
                    else:
                        db.session.add(Patron(
                            badge_id     = row['badge_id'].strip(),
                            first_name   = row['first_name'].strip(),
                            middle_name  = row.get('middle_name', '').strip() or None,
                            last_name    = row['last_name'].strip(),
                            email        = row['email'].strip(),
                            grade        = row['grade'].strip(),
                            status       = row['status'].strip(),
                            rm_num       = row['rm_num'].strip(),
                            guardian_name= row.get('guardian_name', '').strip() or None,
                            phone        = row.get('phone', '').strip() or None,
                            role_id      = role.id,
                            site_id      = site.id,
                        ))
                        added += 1
                db.session.commit()
                db.session.add(BulkUploadLog(
                    filename=f'[Patrons] {filename}',
                    uploaded_by_id=current_user.id,
                    total_records=total,
                    users_added=added,
                    users_updated=updated,
                    status='success' if not row_errors else 'error',
                    error_message='\n'.join(row_errors) if row_errors else None
                ))
                db.session.commit()
                msg = f'Patrons: {added} added, {updated} updated.'
                if row_errors:
                    msg += f' {len(row_errors)} row(s) skipped.'
                flash_messages.append(msg)

            else:
                # Build site lookup cache and validate all rows
                csv_emails = set()
                site_cache = {}
                for row in rows:
                    if not all([row.get('first_name'), row.get('last_name'), row.get('email'),
                                row.get('role_id'), row.get('site_name'), row.get('rm_num')]):
                        raise ValueError('Some rows in the CSV file are missing required fields.')
                    name = row['site_name'].strip()
                    if name not in site_cache:
                        site = _find_site(name)
                        if not site:
                            raise ValueError(f"Site '{name}' not found. Please verify the CSV file.")
                        site_cache[name] = site.id
                    csv_emails.add(row['email'].strip())

                # Upsert users
                _key = current_app.config['SECRET_KEY']
                for row in rows:
                    site_id = site_cache[row['site_name'].strip()]
                    existing_user = User.query.filter_by(email_hash=hash_email(row['email'].strip(), _key)).first()
                    if existing_user:
                        existing_user.first_name  = row['first_name']
                        existing_user.middle_name = row.get('middle_name') or None
                        existing_user.last_name   = row['last_name']
                        existing_user.rm_num      = row.get('rm_num') or existing_user.rm_num
                        existing_user.role_id     = int(row['role_id'])
                        existing_user.site_id     = site_id
                        existing_user.status      = row.get('status') or 'Active'
                        updated += 1
                    else:
                        db.session.add(User(
                            first_name=row['first_name'],
                            middle_name=row.get('middle_name') or None,
                            last_name=row['last_name'],
                            email=row['email'].strip(),
                            status=row.get('status') or 'Active',
                            password_hash=generate_password_hash(secrets.token_urlsafe(16)),
                            must_change_password=True,
                            rm_num=row.get('rm_num') or None,
                            role_id=int(row['role_id']),
                            site_id=site_id
                        ))
                        added += 1

                # Flush pending inserts/updates, then deactivate absent users in one SQL UPDATE
                db.session.flush()
                csv_email_hashes = [hash_email(e, _key) for e in csv_emails]
                deactivated = User.query.filter(
                    User.status == 'Active',
                    ~User.email_hash.in_(csv_email_hashes)
                ).update({'status': 'Inactive'}, synchronize_session=False)

                db.session.commit()
                db.session.add(BulkUploadLog(
                    filename=filename,
                    uploaded_by_id=current_user.id,
                    total_records=total,
                    users_added=added,
                    users_updated=updated,
                    status='success'
                ))
                db.session.commit()
                msg = f'Users: {added} added, {updated} updated.'
                if deactivated:
                    msg += f' {deactivated} marked Inactive (not in file).'
                flash_messages.append(msg)

        except Exception as e:
            db.session.rollback()
            db.session.add(BulkUploadLog(
                filename=f'[Sites] {filename}' if is_sites else (f'[Patrons] {filename}' if is_patrons else filename),
                uploaded_by_id=current_user.id,
                total_records=total,
                users_added=added,
                users_updated=updated,
                status='error',
                error_message=str(e)
            ))
            db.session.commit()
            current_app.logger.error(f"Bulk upload error for {filename}: {e}", exc_info=True)
            flash(f'Error processing {filename}. Check the upload log for details.', 'danger')
            return redirect(url_for('routes.upload_users'))

    if flash_messages:
        flash(' | '.join(flash_messages), 'success')

    return redirect(url_for('routes.upload_users'))


# ****************** FTP Bulk Upload Users *******************************
@routes_blueprint.route('/ftp-settings/save', methods=['POST'])
@login_required
def ftp_save_settings():
    """Save FTP credentials and schedule settings into the Organization record."""
    is_admin()
    org = db.get_or_404(Organization, 1)
    key = current_app.config['SECRET_KEY']

    # --- Credentials ---
    raw_host = re.sub(r'^ftps?://', '', request.form.get('ftp_host', '').strip(), flags=re.IGNORECASE)
    username = request.form.get('ftp_username', '').strip()
    password = request.form.get('ftp_password', '').strip()
    if raw_host:
        org.ftp_host_enc = encrypt_mail_password(raw_host, key)
    if username:
        org.ftp_username_enc = encrypt_mail_password(username, key)
    if password:
        org.ftp_password_enc = encrypt_mail_password(password, key)
    org.ftp_port    = int(request.form.get('ftp_port') or 21)
    org.ftp_path    = request.form.get('ftp_path', '').strip() or None
    org.ftp_use_tls = request.form.get('ftp_use_tls') == 'on'

    # --- Schedule ---
    schedule_enabled = request.form.get('ftp_schedule_enabled') == 'on'
    org.ftp_schedule_enabled = schedule_enabled
    if schedule_enabled:
        schedule_time = (request.form.get('ftp_schedule_time') or '00:00').strip()
        try:
            hour, minute = map(int, schedule_time.split(':'))
        except ValueError:
            hour, minute = 0, 0
        days_list = request.form.getlist('ftp_schedule_days')
        all_days  = {'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'}
        org.ftp_schedule_hour   = hour
        org.ftp_schedule_minute = minute
        org.ftp_schedule_days   = '*' if not days_list or set(days_list) >= all_days else ','.join(days_list)

    # Parse start/stop dates (always save, even when schedule disabled)
    from datetime import date as _date
    def _parse_date(val):
        try:
            return _date.fromisoformat(val.strip()) if val and val.strip() else None
        except ValueError:
            return None
    org.ftp_schedule_start_date = _parse_date(request.form.get('ftp_schedule_start_date', ''))
    org.ftp_schedule_stop_date  = _parse_date(request.form.get('ftp_schedule_stop_date', ''))

    db.session.add(org)
    db.session.commit()

    # Sync APScheduler job (non-fatal if scheduler unavailable)
    try:
        from application.scheduled_jobs import run_org_ftp_schedule
        if schedule_enabled and org.ftp_schedule_hour is not None:
            scheduler.add_job(
                id='org_ftp_schedule',
                func=run_org_ftp_schedule,
                trigger='cron',
                day_of_week=org.ftp_schedule_days,
                hour=org.ftp_schedule_hour,
                minute=org.ftp_schedule_minute,
                replace_existing=True
            )
        else:
            try:
                scheduler.remove_job('org_ftp_schedule')
            except Exception:
                pass
    except Exception:
        pass

    if schedule_enabled:
        flash('FTP settings and schedule saved.', 'success')
    else:
        flash('FTP settings saved. Schedule disabled.', 'success')

    return redirect(url_for('routes.upload_users') + '?tab=ftp')


@routes_blueprint.route('/ftp-upload-users', methods=['POST'])
@login_required
def ftp_bulk_upload_users():
    is_admin()

    ftp_host     = re.sub(r'^ftps?://', '', request.form.get('ftp_host', '').strip(), flags=re.IGNORECASE)
    ftp_port     = request.form.get('ftp_port', '21').strip()
    ftp_username = request.form.get('ftp_username', '').strip()
    ftp_path     = request.form.get('ftp_path', '').strip()
    use_tls      = request.form.get('ftp_use_tls') == 'on'
    ftp_password = request.form.get('ftp_password', '').strip()

    # Fall back to saved org credentials (decrypt) if form fields are blank
    org = db.session.get(Organization, 1)
    if org:
        key = current_app.config['SECRET_KEY']
        if not ftp_host and org.ftp_host_enc:
            ftp_host = decrypt_mail_password(org.ftp_host_enc, key)
        if not ftp_username and org.ftp_username_enc:
            ftp_username = decrypt_mail_password(org.ftp_username_enc, key)
        if not ftp_password and org.ftp_password_enc:
            ftp_password = decrypt_mail_password(org.ftp_password_enc, key)
        ftp_path = ftp_path or (org.ftp_path or '')
        ftp_port = ftp_port or str(org.ftp_port or 21)
        use_tls  = use_tls  or bool(org.ftp_use_tls)

    if not all([ftp_host, ftp_username, ftp_path]):
        flash('FTP host, username, and remote directory are required.', 'danger')
        return redirect(url_for('routes.upload_users') + '?tab=ftp')

    try:
        port = int(ftp_port)
    except ValueError:
        flash('FTP port must be a valid number.', 'danger')
        return redirect(url_for('routes.upload_users') + '?tab=ftp')

    # Normalise: if the stored path still has a .csv filename (old format), strip it
    if ftp_path.lower().endswith('.csv'):
        import posixpath as _pp
        ftp_path = _pp.dirname(ftp_path)
    ftp_dir = ftp_path.rstrip('/')
    users_path   = f'{ftp_dir}/users.csv'
    sites_path   = f'{ftp_dir}/sites.csv'
    patrons_path = f'{ftp_dir}/patrons.csv'

    users_added = users_updated = total_records = 0
    sites_added = sites_updated = sites_total = 0
    patrons_added = patrons_updated = patrons_total = 0

    try:
        ftp = ftplib.FTP_TLS() if use_tls else ftplib.FTP()
        ftp.connect(ftp_host, port, timeout=30)
        ftp.login(ftp_username, ftp_password)
        if use_tls:
            ftp.prot_p()

        # --- Download all files first, then close FTP ---
        sites_buf   = io.BytesIO()
        patrons_buf = io.BytesIO()
        user_buf    = io.BytesIO()

        try:
            ftp.retrbinary(f'RETR {sites_path}', sites_buf.write)
        except ftplib.error_perm:
            sites_buf = None  # not present on server

        try:
            ftp.retrbinary(f'RETR {patrons_path}', patrons_buf.write)
        except ftplib.error_perm:
            patrons_buf = None  # not present on server

        ftp.retrbinary(f'RETR {users_path}', user_buf.write)
        ftp.quit()

        # --- Process sites.csv ---
        if sites_buf is not None:
            sites_buf.seek(0)
            site_rows   = list(csv.DictReader(sites_buf.read().decode('utf-8').splitlines()))
            sites_total = len(site_rows)
            sites_added, sites_updated = _process_sites_rows(site_rows)
            db.session.commit()
            db.session.add(BulkUploadLog(
                filename='[FTP Sites] sites.csv',
                uploaded_by_id=current_user.id,
                total_records=sites_total,
                users_added=sites_added,
                users_updated=sites_updated,
                status='success'
            ))
            db.session.commit()

        user_buf.seek(0)
        rows = list(csv.DictReader(user_buf.read().decode('UTF-8').splitlines()))
        total_records = len(rows)

        # First pass: validate all rows and collect emails
        csv_emails = set()
        for row in rows:
            if not all([row.get('first_name'), row.get('last_name'), row.get('email'),
                        row.get('role_id'), row.get('site_name'), row.get('rm_num')]):
                raise ValueError('Some rows in the CSV file are missing required fields.')
            site = _find_site(row['site_name'])
            if not site:
                raise ValueError(f"Site '{row['site_name'].strip()}' not found. Please verify the CSV file.")
            csv_emails.add(row['email'].strip().lower())

        # Second pass: upsert users
        _ftp_key = current_app.config['SECRET_KEY']
        for row in rows:
            site = _find_site(row['site_name'])
            existing_user = User.query.filter_by(email_hash=hash_email(row['email'].strip(), _ftp_key)).first()
            if existing_user:
                existing_user.first_name  = row['first_name']
                existing_user.middle_name = row.get('middle_name') or None
                existing_user.last_name   = row['last_name']
                existing_user.rm_num      = row.get('rm_num') or existing_user.rm_num
                existing_user.role_id     = int(row['role_id'])
                existing_user.site_id     = site.id
                existing_user.status      = row.get('status') or 'Active'
                users_updated += 1
            else:
                db.session.add(User(
                    first_name=row['first_name'],
                    middle_name=row.get('middle_name', None),
                    last_name=row['last_name'],
                    email=row['email'].strip(),
                    status=row.get('status', 'Active'),
                    password_hash=generate_password_hash(secrets.token_urlsafe(16)),
                    rm_num=row.get('rm_num', None),
                    role_id=row['role_id'],
                    site_id=site.id
                ))
                users_added += 1

        # Third pass: deactivate users absent from the CSV
        users_deactivated = 0
        for user in User.query.filter(User.status == 'Active').all():
            if user.email.strip().lower() not in csv_emails:
                user.status = 'Inactive'
                users_deactivated += 1

        db.session.commit()

        db.session.add(BulkUploadLog(
            filename='[FTP] users.csv',
            uploaded_by_id=current_user.id,
            total_records=total_records,
            users_added=users_added,
            users_updated=users_updated,
            status='success'
        ))
        db.session.commit()

        # --- Process patrons.csv (non-fatal: errors are logged but don't abort) ---
        patrons_error = None
        if patrons_buf is not None:
            try:
                patrons_buf.seek(0)
                patron_rows   = list(csv.DictReader(patrons_buf.read().decode('utf-8').splitlines()))
                patrons_total = len(patron_rows)
                patrons_added, patrons_updated = _process_patrons_rows(patron_rows)
                db.session.commit()
                db.session.add(BulkUploadLog(
                    filename='[FTP Patrons] patrons.csv',
                    uploaded_by_id=current_user.id,
                    total_records=patrons_total,
                    users_added=patrons_added,
                    users_updated=patrons_updated,
                    status='success'
                ))
                db.session.commit()
            except Exception as pe:
                db.session.rollback()
                patrons_error = str(pe)
                db.session.add(BulkUploadLog(
                    filename='[FTP Patrons] patrons.csv',
                    uploaded_by_id=current_user.id,
                    total_records=patrons_total,
                    users_added=patrons_added,
                    users_updated=patrons_updated,
                    status='error',
                    error_message=patrons_error
                ))
                db.session.commit()

        msg = f'FTP import successful: {users_added} users added, {users_updated} updated.'
        if users_deactivated:
            msg += f' {users_deactivated} marked Inactive (not in file).'
        if sites_total:
            msg += f' Sites: {sites_added} added, {sites_updated} updated.'
        if patrons_total and not patrons_error:
            msg += f' Patrons: {patrons_added} added, {patrons_updated} updated.'
        flash(msg, 'success')
        if patrons_error:
            current_app.logger.error(f'FTP patrons import error: {patrons_error}')
            flash('Patrons import encountered errors. Check the upload log for details.', 'warning')

    except (ftplib.Error, OSError, EOFError, UnicodeDecodeError, ValueError) as e:
        db.session.rollback()
        if isinstance(e, socket.gaierror):
            friendly = f"Cannot reach FTP host '{ftp_host}'. Check that the hostname is correct and the server is reachable."
        elif isinstance(e, ConnectionRefusedError):
            friendly = f"Connection refused by '{ftp_host}:{port}'. Check the port number and that the FTP service is running."
        elif isinstance(e, TimeoutError):
            friendly = f"Connection to '{ftp_host}' timed out. The server may be down or blocked by a firewall."
        elif isinstance(e, ftplib.error_perm):
            if any(code in str(e) for code in ('530', '331', '332')):
                friendly = 'FTP login failed. Check your username and password.'
            else:
                current_app.logger.error(f'FTP permission error: {e}')
                friendly = 'FTP permission error. Check your credentials and remote path.'
        else:
            current_app.logger.error(f'FTP bulk upload error: {type(e).__name__}: {e}')
            friendly = 'An unexpected error occurred during the FTP import. Check server logs for details.'
        try:
            db.session.add(BulkUploadLog(
                filename='[FTP] users.csv',
                uploaded_by_id=current_user.id,
                total_records=total_records,
                users_added=users_added,
                users_updated=users_updated,
                status='error',
                error_message=friendly
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
        flash(friendly, 'danger')

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'FTP bulk upload unexpected error: {e}', exc_info=True)
        flash('An unexpected error occurred during the FTP import.', 'danger')

    return redirect(url_for('routes.upload_users'))


# ****************** Bulk Upload Sites (CSV) *******************************
@routes_blueprint.route('/bulk-upload-sites', methods=['POST'])
@login_required
def bulk_upload_sites():
    is_admin()

    if 'csvFile' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('routes.upload_users') + '?tab=sites')

    file = request.files['csvFile']
    if not file or file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('routes.upload_users') + '?tab=sites')

    if not file.filename.lower().endswith('.csv'):
        flash('Invalid file format. Please upload a CSV file.', 'danger')
        return redirect(url_for('routes.upload_users') + '?tab=sites')

    sites_added = sites_updated = total_records = 0
    filename = secure_filename(file.filename)

    try:
        stream = file.read().decode('utf-8')
        rows = list(csv.DictReader(stream.splitlines()))
        total_records = len(rows)
        if total_records == 0:
            flash('The CSV file is empty.', 'warning')
            return redirect(url_for('routes.upload_users') + '?tab=sites')

        sites_added, sites_updated = _process_sites_rows(rows)
        db.session.commit()

        db.session.add(BulkUploadLog(
            filename=f'[Sites] {filename}',
            uploaded_by_id=current_user.id,
            total_records=total_records,
            users_added=sites_added,
            users_updated=sites_updated,
            status='success'
        ))
        db.session.commit()
        flash(f'Sites import successful: {sites_added} added, {sites_updated} updated.', 'success')

    except (UnicodeDecodeError, ValueError) as e:
        db.session.rollback()
        friendly = str(e) if isinstance(e, ValueError) else 'File could not be read. Ensure it is saved as UTF-8 encoded CSV.'
        db.session.add(BulkUploadLog(
            filename=f'[Sites] {filename}',
            uploaded_by_id=current_user.id,
            total_records=total_records,
            users_added=sites_added,
            users_updated=sites_updated,
            status='error',
            error_message=str(e)
        ))
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        flash(f'Sites import failed: {friendly}', 'danger')

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Bulk upload sites unexpected error: {e}', exc_info=True)
        flash('An unexpected error occurred during the sites import.', 'danger')

    return redirect(url_for('routes.upload_users') + '?tab=sites')


# ****************** Bulk Upload Patrons (CSV Tab) *******************************
@routes_blueprint.route('/bulk-upload-patrons-csv', methods=['POST'])
@login_required
def bulk_upload_patrons_csv():
    is_admin()

    if 'csvFile' not in request.files or not request.files['csvFile'].filename:
        flash('No file selected.', 'danger')
        return redirect(url_for('routes.upload_users') + '?tab=patrons')

    file = request.files['csvFile']
    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.csv'):
        flash('Invalid file format. Only .csv files are accepted.', 'danger')
        return redirect(url_for('routes.upload_users') + '?tab=patrons')

    added = updated = total = 0
    required_cols = ['badge_id', 'first_name', 'last_name', 'email', 'grade', 'status', 'rm_num', 'role_name', 'site_name']

    try:
        rows = list(csv.DictReader(file.stream.read().decode('UTF-8').splitlines()))
        total = len(rows)
        errors = []

        for i, row in enumerate(rows, start=2):
            row_errors = []
            missing = [c for c in required_cols if not row.get(c, '').strip()]
            if missing:
                row_errors.append(f"Missing: {', '.join(missing)}")

            role = Role.query.filter(db.func.lower(Role.role_name) == row.get('role_name', '').strip().lower()).first()
            if not role:
                row_errors.append(f"Role '{row.get('role_name', '')}' not found.")

            site = Site.query.filter(db.func.lower(Site.site_name) == row.get('site_name', '').strip().lower()).first()
            if not site:
                row_errors.append(f"Site '{row.get('site_name', '')}' not found.")

            if row_errors:
                errors.append(f"Row {i} ({row.get('badge_id', '')}): {'; '.join(row_errors)}")
                continue

            patron = Patron.query.filter_by(badge_id=row['badge_id'].strip()).first()
            if patron:
                patron.first_name    = row['first_name'].strip()
                patron.middle_name   = row.get('middle_name', '').strip() or None
                patron.last_name     = row['last_name'].strip()
                patron.email         = row['email'].strip()
                patron.grade         = row['grade'].strip()
                patron.status        = row['status'].strip()
                patron.rm_num        = row['rm_num'].strip()
                patron.guardian_name = row.get('guardian_name', '').strip() or None
                patron.phone         = row.get('phone', '').strip() or None
                patron.role_id       = role.id
                patron.site_id       = site.id
                updated += 1
            else:
                db.session.add(Patron(
                    badge_id     = row['badge_id'].strip(),
                    first_name   = row['first_name'].strip(),
                    middle_name  = row.get('middle_name', '').strip() or None,
                    last_name    = row['last_name'].strip(),
                    email        = row['email'].strip(),
                    grade        = row['grade'].strip(),
                    status       = row['status'].strip(),
                    rm_num       = row['rm_num'].strip(),
                    guardian_name= row.get('guardian_name', '').strip() or None,
                    phone        = row.get('phone', '').strip() or None,
                    role_id      = role.id,
                    site_id      = site.id,
                ))
                added += 1

        db.session.commit()
        db.session.add(BulkUploadLog(
            filename=f'[Patrons] {filename}',
            uploaded_by_id=current_user.id,
            total_records=total,
            users_added=added,
            users_updated=updated,
            status='success' if not errors else 'error',
            error_message='\n'.join(errors) if errors else None
        ))
        db.session.commit()

        msg = f'Patrons: {added} added, {updated} updated.'
        if errors:
            msg += f' {len(errors)} row(s) skipped — check the error log.'
            flash(msg, 'warning')
        else:
            flash(msg, 'success')

    except Exception as e:
        db.session.rollback()
        db.session.add(BulkUploadLog(
            filename=f'[Patrons] {filename}',
            uploaded_by_id=current_user.id,
            total_records=total,
            users_added=added,
            users_updated=updated,
            status='error',
            error_message=str(e)
        ))
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        current_app.logger.error(f'Patron bulk upload error: {e}', exc_info=True)
        flash('Patron import failed due to an unexpected error. Check the upload log for details.', 'danger')

    return redirect(url_for('routes.upload_users') + '?tab=patrons')




# *********************************************************************
# ****************** Role Management Page *******************************
@routes_blueprint.route('/roles')
@login_required
def roles():
        # Mapping paths to page names
    page_names = {'/roles': 'Manage User Roles'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    is_admin()  # Ensure only admins can access this route
    # Get the page number and per_page from the query parameters, default to 10 for per_page
    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    # Query the users
    total = Role.query.count()
    roles = Role.query.order_by(Role.id.asc()).offset(offset).limit(per_page).all()    
    # Set up pagination with Bootstrap 5 styling
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('roles.html', roles=roles, pagination=pagination, per_page=per_page, total=total, 
        current_path=current_path, 
        current_page_name=current_page_name
    )

# ****************** Add New Role Page *******************************
@routes_blueprint.route('/add_role', methods=['GET', 'POST'])
@login_required
def add_role():
            # Mapping paths to page names
    page_names = {'/add_role': 'New Role'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    is_admin()  # Ensure only admins can access this route
    form = RoleForm()
    if form.validate_on_submit():
        # Check if a role with the same name already exists
        existing_role = Role.query.filter_by(role_name=form.role_name.data).first()
        if existing_role:
            flash('This role already exists.', 'danger')
            return render_template('add_role.html', form=form)  # Re-render form with the error message
        # Create and add the new role
        new_role = Role(
            role_name=form.role_name.data
        )
        db.session.add(new_role)
        db.session.commit()
        flash('Role added successfully!', 'success')
        return redirect(url_for('routes.roles'))
    return render_template('add_role.html', form=form,
        current_path=current_path, 
        current_page_name=current_page_name)

# ****************** Edit Role Page *******************************
@routes_blueprint.route('/edit_role/<int:role_id>', methods=['GET', 'POST'])
@login_required
def edit_role(role_id):
    is_admin()  # Ensure only admins can access this route
    
    # Restrict editing roles with IDs 1, 2, 3, 4, 5
    if role_id in {1, 2, 3, 4, 5}:
        flash('You are not allowed to edit this role.', 'danger')
        return redirect(url_for('routes.roles'))

    role = db.get_or_404(Role, role_id)
    form = RoleForm(obj=role)
    if form.validate_on_submit():
        # Check for duplicate entries
        existing_role = Role.query.filter(Role.role_name == form.role_name.data, Role.id != role.id).first()
        if existing_role:
            flash('This role already exists.', 'danger')
            return render_template('add_role.html', form=form)  # Re-render form with the error message
        # Check if there are any changes to the form
        if (
            role.role_name == form.role_name.data
        ):
            flash('No changes were made.', 'info')
            return render_template('edit_role.html', form=form, role=role)
        role.role_name = form.role_name.data
        db.session.commit()
        flash('Role updated successfully!', 'success')
        return redirect(url_for('routes.roles'))
    return render_template('edit_role.html', form=form, role=role)


# ****************** Delete Role Page *******************************
@routes_blueprint.route('/delete_role/<int:role_id>', methods=['POST'])
@login_required
def delete_role(role_id):
    is_admin()  # Ensure only admins can access this route

    # Restrict deleting roles with IDs 1, 2, 3, 4, 5
    if role_id in {1, 2, 3, 4, 5}:
        flash('You are not allowed to delete this role.', 'danger')
        return redirect(url_for('routes.roles'))
    
    role = db.get_or_404(Role, role_id)
    db.session.delete(role)
    db.session.commit()
    flash('Role deleted successfully!', 'warning')
    return redirect(url_for('routes.roles'))


# *********************************************************************
# ****************** Site Management Page *******************************
@routes_blueprint.route('/sites', methods=['GET'])
@login_required
def sites():
        # Mapping paths to page names
    page_names = {'/sites': 'Manage Sites'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    is_admin()  # Ensure only admins can access this route
    # Get the page number and per_page from the query parameters, default to 10 for per_page
    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    # Query the users
    total = Site.query.count()
    sites = Site.query.order_by(Site.id.asc()).offset(offset).limit(per_page).all()
    # Set up pagination with Bootstrap 5 styling
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('sites.html', sites=sites, pagination=pagination, per_page=per_page, total=total, 
        current_path=current_path, 
        current_page_name=current_page_name
    )

# ****************** Add New Site Page *******************************
@routes_blueprint.route('/add_site', methods=['GET', 'POST'])
@login_required
def add_site():
            # Mapping paths to page names
    page_names = {'/add_site': 'New Site'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    is_admin()  # Ensure only admins can access this route
    form = SiteForm()
    if form.validate_on_submit():
        # Check if a role with the same name already exists
        existing_site = Site.query.filter_by(site_cds=form.site_cds.data).first()
        if existing_site:
            flash('This site already exists.', 'danger')
            return render_template('add_site.html', form=form,
                current_path=current_path, current_page_name=current_page_name)
        new_site = Site(
            site_name=form.site_name.data,
            site_acronyms=form.site_acronyms.data,
            site_code=form.site_code.data,
            site_cds=form.site_cds.data,
            site_address=form.site_address.data,
            site_type=form.site_type.data 
        )
        db.session.add(new_site)
        db.session.commit()
        flash('Site added successfully!', 'success')
        return redirect(url_for('routes.sites'))
    # Pass None for site to differentiate between add and edit
    return render_template('add_site.html', form=form,
        current_path=current_path, 
        current_page_name=current_page_name
    )


# ****************** Edit Site Page *******************************
@routes_blueprint.route('/edit_site/<int:site_id>', methods=['GET', 'POST'])
@login_required
def edit_site(site_id):
    is_admin()  # Ensure only admins can access this route
    site = db.get_or_404(Site, site_id)
    form = SiteForm(obj=site)
    # Ensure stored value is a valid choice; fall back to first option for legacy free-text data
    valid_types = [c[0] for c in form.site_type.choices]
    if not request.form and site.site_type not in valid_types:
        form.site_type.data = valid_types[0]
    if form.validate_on_submit():
        # Check if a role with the same name already exists
        existing_site = Site.query.filter(Site.site_cds == form.site_cds.data, Site.id != site.id).first()
        if existing_site:
            flash('This site already exists.', 'danger')
            return render_template('edit_site.html', form=form, site=site)
        # Check if there are any changes to the form
        if (
            site.site_name == form.site_name.data and
            site.site_acronyms == form.site_acronyms.data and
            site.site_code == form.site_code.data and
            site.site_cds == form.site_cds.data and
            site.site_address == form.site_address.data and
            site.site_type == form.site_type.data
        ):
            flash('No changes were made.', 'info')
            return render_template('edit_site.html', form=form, site=site,
                current_path=request.path, current_page_name='Edit Site')
        site.site_name = form.site_name.data
        site.site_acronyms = form.site_acronyms.data
        site.site_code = form.site_code.data
        site.site_cds = form.site_cds.data
        site.site_address = form.site_address.data
        site.site_type = form.site_type.data
        db.session.commit()
        flash('Site updated successfully!', 'success')
        return redirect(url_for('routes.sites'))
    return render_template('edit_site.html', form=form, site=site)

# ****************** Delete Site Page *******************************
@routes_blueprint.route('/delete_site/<int:site_id>', methods=['POST'])
@login_required
def delete_site(site_id):
    is_admin()  # Ensure only admins can access this route
    site = db.get_or_404(Site, site_id)
    db.session.delete(site)
    db.session.commit()
    flash('Site deleted successfully!', 'warning')
    return redirect(url_for('routes.sites'))


# *********************************************************************
# ****************** Notification Management Page *********************
@routes_blueprint.route('/notifications', methods=['GET'])
@login_required
def notifications():
        # Mapping paths to page names
    page_names = {'/notifications': 'Manage Notifications'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    is_admin()  # Ensure only admins can access this route
    # Get the page number and per_page from the query parameters, default to 10 for per_page
    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    # Query the users
    total = Notification.query.count()
    notifications = Notification.query.offset(offset).limit(per_page).all()
    # Set up pagination with Bootstrap 5 styling
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('notifications.html', notifications=notifications, pagination=pagination, per_page=per_page, total=total, 
        current_path=current_path, 
        current_page_name=current_page_name
    )

# ****************** Add New Notification *********************
@routes_blueprint.route('/add_notification', methods=['GET', 'POST'])
@login_required
def add_notification():
    page_names = {'/add_notification': 'New Notification'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    is_admin()  # Ensure only admins can access this route
    form = NotificationForm()
    if form.validate_on_submit():
        # Check if a notification with the same name already exists
        existing_notification = Notification.query.filter_by(msg_name=form.msg_name.data).first()
        if existing_notification:
            flash('This notification name already exists.', 'danger')
            return render_template('add_notification.html', form=form)  # Re-render form with the error message
        new_notification = Notification(
            msg_name=form.msg_name.data,
            msg_content=form.msg_content.data,
            msg_status="Inactive"
        )
        db.session.add(new_notification)
        db.session.commit()
        flash('Notification added successfully!', 'success')
        return redirect(url_for('routes.notifications'))
    # Pass None for notification to differentiate between add and edit
    return render_template('add_notification.html', form=form,
        current_path=current_path, 
        current_page_name=current_page_name
    )


# ****************** Edit Notification Page *********************
@routes_blueprint.route('/edit_notification/<int:notification_id>', methods=['GET', 'POST'])
@login_required
def edit_notification(notification_id):
    is_admin()  # Ensure only admins can access this route
    notification = db.get_or_404(Notification, notification_id)
    form = NotificationForm(obj=notification)

    if request.method == 'POST':
        # Capture original values before any mutation
        orig_name    = notification.msg_name
        orig_content = notification.msg_content
        orig_status  = notification.msg_status

        # Determine new status from checkbox
        new_status = 'Active' if request.form.get('msg_status') else 'Inactive'

        # Check for duplicate notification name
        existing_notification = Notification.query.filter(
            Notification.msg_name == form.msg_name.data,
            Notification.id != notification.id
        ).first()
        if existing_notification:
            flash('This notification name already exists.', 'danger')
            return render_template('edit_notification.html', form=form, notification=notification)

        # Check if no changes were made
        if (
            orig_name    == form.msg_name.data and
            orig_content == form.msg_content.data and
            orig_status  == new_status
        ):
            flash('No changes were made.', 'info')
            return render_template('edit_notification.html', form=form, notification=notification)

        # Enforce only one active notification
        if new_status == 'Active':
            active_notification = Notification.query.filter_by(msg_status='Active').first()
            if active_notification and active_notification.id != notification.id:
                flash('Only one notification can be active at a time. Please deactivate the current notification before activating a new one. ', 'danger')
                return render_template('edit_notification.html', form=form, notification=notification)

        # Update and save changes
        notification.msg_name    = form.msg_name.data
        notification.msg_content = form.msg_content.data
        notification.msg_status  = new_status
        db.session.commit()
        flash('Notification updated successfully!', 'success')
        return redirect(url_for('routes.notifications'))

    return render_template('edit_notification.html', form=form, notification=notification)



# ****************** Toggle Notification Status *********************
@routes_blueprint.route('/toggle_notification/<int:notification_id>', methods=['POST'])
@login_required
def toggle_notification(notification_id):
    is_admin()
    notification = db.get_or_404(Notification, notification_id)
    if notification.msg_status == 'Active':
        notification.msg_status = 'Inactive'
    else:
        # Deactivate all others first, then activate this one
        Notification.query.filter(Notification.id != notification_id).update({'msg_status': 'Inactive'})
        notification.msg_status = 'Active'
    db.session.commit()
    return redirect(url_for('routes.notifications'))


# ****************** Delete Notification Page *********************
@routes_blueprint.route('/delete_notification/<int:notification_id>', methods=['POST'])
@login_required
def delete_notification(notification_id):
    is_admin()  # Ensure only admins can access this route
    notification = db.get_or_404(Notification, notification_id)
    db.session.delete(notification)
    db.session.commit()
    flash('Notification deleted successfully!', 'warning')
    return redirect(url_for('routes.notifications'))







# *********************************************************************
# ****************** Dashboard Page *******************************
@routes_blueprint.route('/devices', methods=['GET'])
@login_required
def devices():
    page_names = {'/devices': 'Devices'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')

    search = request.args.get('search', '').strip()
    default_site = '' if current_user.is_admin else str(current_user.site_id)
    site_filter = request.args.get('site_filter', default_site)
    category_filter = request.args.get('category_filter', '')
    availability_filter = request.args.get('availability_filter', '')
    per_page = request.args.get('per_page', 10, type=int)
    page, _, _ = get_page_args(page_parameter='page', per_page_parameter='per_page')

    query = Device.query

    if search:
        query = query.filter(
            db.or_(
                Device.serial_num.ilike(f'%{search}%'),
                Device.device_tag.ilike(f'%{search}%'),
                Device.brand_name.ilike(f'%{search}%'),
                Device.model_name.ilike(f'%{search}%'),
            )
        )

    if site_filter:
        query = query.filter(Device.site_id == int(site_filter))

    if category_filter:
        query = query.filter(Device.category_id == int(category_filter))

    if availability_filter == 'available':
        query = query.filter(
            db.or_(Device.assigned_to_id == None, Device.return_at != None)
        )
    elif availability_filter == 'checked_out':
        query = query.filter(Device.assigned_to_id != None, Device.return_at == None)
    elif availability_filter == 'in_repair':
        query = query.filter(Device.in_repair == True)

    total = query.count()
    devices = query.offset((page - 1) * per_page).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')

    sites = Site.query.order_by(Site.site_name).all()
    categories = Category.query.order_by(Category.category_name).all()

    return render_template(
        "devices.html",
        devices=devices,
        sites=sites,
        categories=categories,
        per_page=per_page,
        pagination=pagination,
        current_path=current_path,
        current_page_name=current_page_name,
        site_filter=site_filter,
        category_filter=category_filter,
        availability_filter=availability_filter,
    )



# ****************** Add New Device Page *******************************
# ── Device audit-trail helpers ────────────────────────────────────────────────
_DEVICE_TRACKED_FIELDS = [
    ('assigned_to_id', 'Assigned To'),
    ('device_condition', 'Condition'),
    ('site_id',         'Site'),
    ('in_repair',       'In Repair'),
    ('return_at',       'Return Date'),
    ('chkout_at',       'Check Out Date'),
    ('device_tag',      'Device Tag'),
    ('serial_num',      'Serial Number'),
    ('brand_name',      'Brand'),
    ('model_name',      'Model'),
    ('category_id',     'Category'),
    ('comments',        'Comments'),
]

def _device_field_label(attr, value):
    """Return a human-readable string for a device field value."""
    if attr == 'assigned_to_id':
        if not value:
            return 'Unassigned'
        p = db.session.get(Patron, value)
        return p.get_patron_name() if p else f'Patron #{value}'
    if attr == 'site_id':
        s = db.session.get(Site, value)
        return s.site_name if s else f'Site #{value}'
    if attr == 'category_id':
        c = db.session.get(Category, value)
        return c.category_name if c else f'Category #{value}'
    if attr == 'in_repair':
        return 'Yes' if value else 'No'
    if attr in ('return_at', 'chkout_at'):
        if not value:
            return '—'
        return value.strftime('%m/%d/%Y') if hasattr(value, 'strftime') else str(value)
    return str(value) if value is not None else ''

def _snapshot_device(device):
    """Capture current field values for comparison before saving."""
    return {attr: getattr(device, attr) for attr, _ in _DEVICE_TRACKED_FIELDS}

def _log_device_changes(device_id, user_id, old_snap, new_snap):
    """Insert DeviceHistory rows for every field that changed."""
    entries = []
    for attr, label in _DEVICE_TRACKED_FIELDS:
        old_val = old_snap.get(attr)
        new_val = new_snap.get(attr)
        if old_val != new_val:
            entries.append(DeviceHistory(
                device_id=device_id,
                changed_by_id=user_id,
                action='updated',
                field_name=label,
                old_value=_device_field_label(attr, old_val),
                new_value=_device_field_label(attr, new_val),
            ))
    if entries:
        for e in entries:
            db.session.add(e)
        db.session.commit()
# ─────────────────────────────────────────────────────────────────────────────


@routes_blueprint.route('/add_device', methods=['GET', 'POST'])
@login_required
def add_device():
    page_names = {'/add_device': 'New Device'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    if not (current_user.is_admin or current_user.is_tech_role):
        abort(403)

    form = DeviceForm()
    # Populate dropdowns
    form.category_id.choices = [(c.id, c.category_name) for c in Category.query.order_by(Category.category_name).all()]
    form.site_id.choices = [(s.id, s.site_name) for s in Site.query.order_by(Site.site_name).all()]
    # assigned_to_id is set via the patron-picker modal (AJAX), no choices needed

    if form.validate_on_submit():
        # Prevent duplicate serial number
        existing_device = Device.query.filter_by(serial_num=form.serial_num.data).first()
        if existing_device:
            flash('This device already exists.', 'danger')
            return render_template(
                'add_device.html',
                form=form,
                current_path=current_path,
                current_page_name=current_page_name
            )

        new_device = Device(
            category_id=form.category_id.data,
            serial_num=form.serial_num.data,
            device_tag=form.device_tag.data or None,
            model_name=form.model_name.data.title(),
            brand_name=form.brand_name.data.title(),
            device_condition=form.device_condition.data,
            site_id=form.site_id.data,
            assigned_to_id=form.assigned_to_id.data or None,
            comments=form.comments.data,
            user_id=current_user.id,
            return_at=None  # Ensure return date is empty
        )
        db.session.add(new_device)
        db.session.commit()
        # Log creation
        db.session.add(DeviceHistory(
            device_id=new_device.id,
            changed_by_id=current_user.id,
            action='created',
        ))
        db.session.commit()
        flash('Device added successfully!', 'success')
        return redirect(url_for('routes.devices'))

    return render_template(
        'add_device.html',
        form=form,
        current_path=current_path,
        current_page_name=current_page_name
    )

# ****************** Add New Device Page *******************************
# -----------------------
# Edit device
# -----------------------
@routes_blueprint.route('/edit_device/<int:device_id>', methods=['GET', 'POST'])
@login_required
def edit_device(device_id):
    device = db.get_or_404(Device, device_id)
    form = DeviceForm(obj=device)

    # Populate dropdowns
    form.site_id.choices = [(s.id, s.site_name) for s in Site.query.all()]
    form.assigned_to_id.choices = [(0, "Unassigned")] + [
        (u.id, u.get_patron_name()) for u in Patron.query.all()
    ]
    form.category_id.choices = [(c.id, c.category_name) for c in Category.query.all()]

    if form.validate_on_submit():
        old_snap = _snapshot_device(device)

        device.category_id = form.category_id.data
        device.serial_num = form.serial_num.data
        device.device_tag = form.device_tag.data or None
        device.brand_name = form.brand_name.data.title()
        device.model_name = form.model_name.data.title()
        device.device_condition = form.device_condition.data
        device.comments = form.comments.data
        device.site_id = form.site_id.data
        device.assigned_to_id = form.assigned_to_id.data if form.assigned_to_id.data != 0 else None
        device.chkout_at = form.chkout_at.data
        device.return_at = form.return_at.data

        new_in_repair = form.in_repair.data
        if new_in_repair and not device.in_repair:
            device.repair_date = datetime.now(timezone.utc)
        elif not new_in_repair:
            device.repair_date = None
        device.in_repair = new_in_repair

        db.session.commit()

        new_snap = _snapshot_device(device)
        _log_device_changes(device.id, current_user.id, old_snap, new_snap)

        flash("Device updated successfully!", "success")
        return redirect(url_for('routes.edit_device', device_id=device_id))
    return render_template("edit_device.html", form=form, device=device)


# ****************** Add Repair Comment *******************************
@routes_blueprint.route('/device/<int:device_id>/add_comment', methods=['POST'])
@login_required
def add_device_comment(device_id):
    db.get_or_404(Device, device_id)
    content = request.form.get('content', '').strip()
    if content:
        comment = DeviceComment(device_id=device_id, user_id=current_user.id, content=content)
        db.session.add(comment)
        db.session.commit()
        flash('Comment added.', 'success')
    return redirect(url_for('routes.edit_device', device_id=device_id))


@routes_blueprint.route('/delete_device/<int:device_id>', methods=['POST', 'GET'])
@login_required
def delete_device(device_id):
    device = db.get_or_404(Device, device_id)
    db.session.delete(device)
    db.session.commit()
    flash('Device deleted successfully.', 'success')
    return redirect(url_for('routes.devices'))


@routes_blueprint.route('/checkin_device/<int:device_id>', methods=['POST'])
@login_required
def checkin_device(device_id):
    if not (current_user.is_admin or current_user.is_tech_role):
        abort(403)
    device = db.get_or_404(Device, device_id)
    old_snap = _snapshot_device(device)
    device.assigned_to_id = None
    device.return_at = datetime.now(timezone.utc)
    db.session.commit()
    new_snap = _snapshot_device(device)
    _log_device_changes(device.id, current_user.id, old_snap, new_snap)
    flash('Device checked in.', 'success')
    return redirect(url_for('routes.devices'))









# *********************************************************************
# ****************** Category Management Page *******************************
@routes_blueprint.route('/categories')
@login_required
def categories():
        # Mapping paths to page names
    page_names = {'/categories': 'Manage Device Categories'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    if not (current_user.is_admin or current_user.is_tech_role):
        abort(403)

    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    total = Category.query.count()
    categories = Category.query.order_by(Category.category_name.asc()).offset(offset).limit(per_page).all()
    # Set up pagination with Bootstrap 5 styling
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('categories.html', categories=categories, pagination=pagination, per_page=per_page, total=total, 
        current_path=current_path, 
        current_page_name=current_page_name
    )


# ****************** Add Category Page *******************************
@routes_blueprint.route('/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
        # Mapping paths to page names
    page_names = {'/add_category': 'New Device Category'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    if not (current_user.is_admin or current_user.is_tech_role):
        abort(403)

    form = CategoryForm()
    if form.validate_on_submit():
        # Check if a Category with the same name already exists
        existing_category = Category.query.filter_by(category_name=form.category_name.data).first()
        if existing_category:
            flash('This category already exists.', 'danger')
            return render_template('add_category.html', form=form)  # Re-render form with the error message
        # Create and add the new category
        new_category = Category(
            category_name=form.category_name.data
        )
        db.session.add(new_category)
        db.session.commit()
        flash('Category added successfully!', 'success')
        return redirect(url_for('routes.categories'))
    return render_template('add_category.html', form=form, 
        current_path=current_path, 
        current_page_name=current_page_name
    )

# ****************** Edit Category Page *******************************
@routes_blueprint.route('/edit_category/<int:category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    is_admin()  # Ensure only admins can access this route
    category = db.get_or_404(Category, category_id)
    form = CategoryForm(obj=category)

    if form.validate_on_submit():
        # Check for duplicate entries
        existing_category = Category.query.filter(
            Category.category_name == form.category_name.data.title(),
            Category.id != category.id
        ).first()
        if existing_category:
            flash('This category already exists.', 'danger')
            return render_template('edit_category.html', form=form, category=category)

        # Check if there are any changes
        if category.category_name == form.category_name.data:
            flash('No changes were made.', 'info')
            return render_template('edit_category.html', form=form, category=category)

        # ✅ update correctly
        category.category_name = form.category_name.data
        db.session.commit()

        flash('Device category updated successfully!', 'success')
        return redirect(url_for('routes.categories'))

    return render_template('edit_category.html', form=form, category=category)



# ****************** Delete category Page *******************************
@routes_blueprint.route('/delete_category/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    is_admin()  # Ensure only admins can access this route
    category = db.get_or_404(Category, category_id)
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully!', 'warning')
    return redirect(url_for('routes.categories'))




# # *********************************************************************
# # ****************** Patron Management Page *******************************
# @routes_blueprint.route('/patron_detail/<int:patron_id>', methods=['GET'])
# @login_required
# def patron_detail(patron_id):
#     # Ensure only admins or techs can access
#     if current_user.is_admin:
#         is_admin()
#     elif current_user.is_tech_role:
#         is_tech_role()

#     # Get patron with role info
#     patron = (
#         db.session.query(
#             Patron.id,
#             Patron.first_name,
#             Patron.middle_name,
#             Patron.last_name,
#             Patron.email,
#             Patron.rm_num,
#             Role.name.label("role_name")
#         )
#         .join(Role, Role.id == Patron.role_id)
#         .filter(Patron.id == patron_id)
#         .first_or_404()
#     )

#     # Dynamic page name
#     current_page_name = f"Patron Profile - {patron.first_name} {patron.last_name}"

#     return render_template(
#         'patron_detail.html',
#         patron=patron,
#         current_page_name=current_page_name
#     )








# *********************************************************************
# ****************** Patrons Management Page ****************************
@routes_blueprint.route('/patrons', methods=['GET'])
@login_required
def patrons():
    page_names = {'/patrons': 'Manage Patrons'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')
    
    if not (current_user.is_admin or current_user.is_tech_role):
        abort(403)

    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    search = request.args.get('search', '').strip()
    default_site = '' if current_user.is_admin else str(current_user.site_id)
    site_filter = request.args.get('site_filter', default_site).strip()
    role_filter = request.args.get('role_filter', '').strip()
    grade_filter = request.args.get('grade_filter', '').strip()
    status_filter = request.args.get('status_filter', '').strip()
    room_filter = request.args.get('room_filter', '').strip()

    query = Patron.query

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                Patron.first_name.ilike(search_pattern),
                Patron.middle_name.ilike(search_pattern),
                Patron.last_name.ilike(search_pattern),
                Patron.badge_id.ilike(search_pattern),
                func.concat(Patron.first_name, " ", Patron.last_name).ilike(search_pattern),
                func.concat(Patron.first_name, " ", Patron.middle_name, " ", Patron.last_name).ilike(search_pattern)
            )
        )

    if site_filter:
        try:
            query = query.filter(Patron.site_id == int(site_filter))
        except ValueError:
            pass

    if role_filter:
        try:
            query = query.filter(Patron.role_id == int(role_filter))
        except ValueError:
            pass

    if grade_filter:
        query = query.filter(Patron.grade == grade_filter)

    if status_filter:
        query = query.filter(Patron.status == status_filter)

    if room_filter:
        query = query.filter(Patron.rm_num == room_filter)

    total = query.count()
    patrons = query.order_by(Patron.first_name.asc()).offset(offset).limit(per_page).all()

    sites = Site.query.order_by(Site.site_name.asc()).all()
    roles = Role.query.order_by(Role.role_name.asc()).all()
    rooms = [r[0] for r in db.session.query(Patron.rm_num).filter(
        Patron.rm_num.isnot(None), Patron.rm_num != ''
    ).distinct().order_by(Patron.rm_num.asc()).all()]

    pagination = Pagination(page=page, per_page=per_page, total=total)

    return render_template(
        'patrons.html',
        patrons=patrons,
        pagination=pagination,
        per_page=per_page,
        total=total,
        current_path=current_path,
        current_page_name=current_page_name,
        sites=sites,
        roles=roles,
        rooms=rooms,
        search=search,
        site_filter=site_filter,
        role_filter=role_filter,
        grade_filter=grade_filter,
        status_filter=status_filter,
        room_filter=room_filter
    )




# ****************** Bulk Upload Patrons *******************************
@routes_blueprint.route('/bulk-upload-patrons', methods=['GET', 'POST'])
@login_required
def bulk_upload_patrons():
    is_admin()

    if request.method == 'GET':
        return render_template('bulk_upload_patrons.html',
                               processed=False, added=0, updated=0, errors=[],
                               current_page_name='Bulk Upload Patrons',
                               current_path=request.path)

    if 'csvFile' not in request.files or not request.files['csvFile'].filename:
        flash('No file selected.', 'danger')
        return redirect(url_for('routes.bulk_upload_patrons'))

    file = request.files['csvFile']
    if not file.filename.lower().endswith('.csv'):
        flash('Invalid file format. Only .csv files are accepted.', 'danger')
        return redirect(url_for('routes.bulk_upload_patrons'))

    added = updated = 0
    errors = []
    required_cols = ['badge_id', 'first_name', 'last_name', 'email', 'grade', 'status', 'rm_num', 'role_name', 'site_name']

    try:
        rows = list(csv.DictReader(file.stream.read().decode('UTF-8').splitlines()))
    except UnicodeDecodeError:
        flash('Could not read file. Ensure it is saved as UTF-8 encoded CSV.', 'danger')
        return redirect(url_for('routes.bulk_upload_patrons'))

    for i, row in enumerate(rows, start=2):
        row_errors = []
        missing = [c for c in required_cols if not row.get(c, '').strip()]
        if missing:
            row_errors.append(f"Missing required fields: {', '.join(missing)}")

        role = Role.query.filter(db.func.lower(Role.role_name) == row.get('role_name', '').strip().lower()).first()
        if not role:
            row_errors.append(f"Role '{row.get('role_name', '')}' not found.")

        site = Site.query.filter(db.func.lower(Site.site_name) == row.get('site_name', '').strip().lower()).first()
        if not site:
            row_errors.append(f"Site '{row.get('site_name', '')}' not found.")

        if row_errors:
            errors.append({'row': i, 'badge_id': row.get('badge_id', ''), 'reasons': row_errors})
            continue

        patron = Patron.query.filter_by(badge_id=row['badge_id'].strip()).first()
        if patron:
            patron.first_name    = row['first_name'].strip()
            patron.middle_name   = row.get('middle_name', '').strip() or None
            patron.last_name     = row['last_name'].strip()
            patron.email         = row['email'].strip()
            patron.grade         = row['grade'].strip()
            patron.status        = row['status'].strip()
            patron.rm_num        = row['rm_num'].strip()
            patron.guardian_name = row.get('guardian_name', '').strip() or None
            patron.phone         = row.get('phone', '').strip() or None
            patron.role_id       = role.id
            patron.site_id       = site.id
            updated += 1
        else:
            db.session.add(Patron(
                badge_id     = row['badge_id'].strip(),
                first_name   = row['first_name'].strip(),
                middle_name  = row.get('middle_name', '').strip() or None,
                last_name    = row['last_name'].strip(),
                email        = row['email'].strip(),
                grade        = row['grade'].strip(),
                status       = row['status'].strip(),
                rm_num       = row['rm_num'].strip(),
                guardian_name= row.get('guardian_name', '').strip() or None,
                phone        = row.get('phone', '').strip() or None,
                role_id      = role.id,
                site_id      = site.id,
            ))
            added += 1

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Patron bulk upload DB error: {e}', exc_info=True)
        flash('A database error occurred during the patron import. Check server logs for details.', 'danger')
        return redirect(url_for('routes.bulk_upload_patrons'))

    return render_template('bulk_upload_patrons.html',
                           processed=True, added=added, updated=updated, errors=errors,
                           current_page_name='Bulk Upload Patrons',
                           current_path=request.path)


# ****************** Add Patron Page *******************************
@routes_blueprint.route('/add_patron', methods=['GET', 'POST'])
@login_required
def add_patron():
    is_admin()  # Ensure only admins can access this route
    # Mapping paths to page names
    page_names = {'/add_patron': 'Add Patron'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')

    form = PatronForm()
    form.role_id.choices = [(role.id, role.role_name) for role in Role.query.all()]
    form.site_id.choices = [(site.id, site.site_name) for site in Site.query.all()]
    if form.validate_on_submit():
        # Check if a Patron with the same email already exists
        _key = current_app.config['SECRET_KEY']
        existing_user = Patron.query.filter_by(email_hash=hash_email(form.email.data.strip(), _key)).first()
        if existing_user:
            flash('A patron with this email already exists. Please use a different email.', 'danger')
            return render_template('add_patron.html', form=form)  # Re-render form with the error message
        new_user = Patron(
            badge_id=form.badge_id.data,
            first_name=form.first_name.data.title(),
            middle_name=form.middle_name.data.title() if form.middle_name.data else None,
            last_name=form.last_name.data.title(),
            email=form.email.data,
            grade=form.grade.data,
            status=form.status.data,
            rm_num=form.rm_num.data,
            guardian_name=form.guardian_name.data.title() if form.guardian_name.data else None,
            phone=form.phone.data,
            site_id=form.site_id.data,
            role_id=form.role_id.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Patrons added successfully!', 'success')
        return redirect(url_for('routes.patrons'))
    return render_template('add_patron.html', form=form,current_path=current_path,
        current_page_name=current_page_name)



# ****************** Edit Patron Page *******************************
@routes_blueprint.route('/edit_patron/<int:patron_id>', methods=['GET', 'POST'])
@login_required
def edit_patron(patron_id):
    is_admin()  # Ensure only admins can access this route
    # Mapping paths to page names
    page_names = {'/edit_patron': 'Edit Patron'}
    current_path = request.path
    current_page_name = page_names.get(current_path, 'Unknown Page')

    patron = db.get_or_404(Patron, patron_id)
    form = PatronForm(obj=patron)
    form.role_id.choices = [(role.id, role.role_name) for role in Role.query.all()]
    form.site_id.choices = [(site.id, site.site_name) for site in Site.query.all()]
    if form.validate_on_submit():
        # Check if a Patron with the same email already exists (excluding the current patron)
        _key = current_app.config['SECRET_KEY']
        existing_user = Patron.query.filter_by(email_hash=hash_email(form.email.data.strip(), _key)).first()
        if existing_user and existing_user.id != patron_id:
            flash('A patron with this email already exists. Please use a different email.', 'danger')
            return render_template('edit_patron.html', form=form, patron=patron)

        # Update the patron's information
        patron.badge_id = form.badge_id.data
        patron.first_name = form.first_name.data.title()
        patron.middle_name = form.middle_name.data.title() if form.middle_name.data else None
        patron.last_name = form.last_name.data.title()
        patron.email = form.email.data
        patron.grade = form.grade.data
        patron.status = form.status.data
        patron.rm_num = form.rm_num.data
        patron.guardian_name = form.guardian_name.data.title() if form.guardian_name.data else None
        patron.phone = form.phone.data
        patron.site_id = form.site_id.data
        patron.role_id = form.role_id.data

        db.session.commit()
        flash('Patron updated successfully!', 'success')
        return redirect(url_for('routes.patrons'))
    return render_template('edit_patron.html', form=form, patron=patron,current_path=current_path,
                            current_page_name=current_page_name)

# ****************** Patron Details Page *******************************
@routes_blueprint.route('/patron_details/<int:patron_id>', methods=['GET'])
@login_required
def patron_details(patron_id):
    patron = db.get_or_404(Patron, patron_id)
    return render_template('patron_details.html', patron=patron,
                           current_page_name='Patron Details',
                           current_path=request.path)


# ****************** Search Patrons (AJAX) *******************************
@routes_blueprint.route('/search_patrons')
@login_required
def search_patrons():
    q = request.args.get('q', '').strip()
    query = Patron.query.filter_by(status='Active')
    if q:
        query = query.filter(
            db.or_(
                Patron.first_name.ilike(f'%{q}%'),
                Patron.last_name.ilike(f'%{q}%'),
                Patron.badge_id.ilike(f'%{q}%'),
            )
        )
    patrons = query.limit(20).all()
    return jsonify([{
        'id': p.id,
        'name': p.get_patron_name(),
        'badge_id': p.badge_id,
        'grade': p.grade,
        'site': p.site.site_name if p.site else 'N/A',
    } for p in patrons])


# ****************** Search Available Devices (AJAX) *******************************
@routes_blueprint.route('/search_available_devices')
@login_required
def search_available_devices():
    q = request.args.get('q', '').strip()
    query = Device.query.filter(
        db.or_(Device.assigned_to_id == None, Device.return_at != None)
    )
    if q:
        query = query.filter(
            db.or_(
                Device.serial_num.ilike(f'%{q}%'),
                Device.device_tag.ilike(f'%{q}%'),
                Device.brand_name.ilike(f'%{q}%'),
                Device.model_name.ilike(f'%{q}%'),
            )
        )
    devices = query.limit(20).all()
    return jsonify([{
        'id': d.id,
        'device_tag': d.device_tag or 'N/A',
        'serial_num': d.serial_num,
        'brand_name': d.brand_name,
        'model_name': d.model_name,
        'device_condition': d.device_condition,
    } for d in devices])


# ****************** Assign Device to Patron *******************************
@routes_blueprint.route('/assign_device/<int:patron_id>', methods=['POST'])
@login_required
def assign_device(patron_id):
    patron = db.get_or_404(Patron, patron_id)
    device_id = request.form.get('device_id', type=int)
    device = db.get_or_404(Device, device_id)
    device.assigned_to_id = patron_id
    device.chkout_at = datetime.now(timezone.utc)
    device.return_at = None
    db.session.commit()
    flash(f'Device assigned to {patron.get_patron_name()} successfully!', 'success')
    return redirect(url_for('routes.patron_details', patron_id=patron_id))


# ****************** Return Device Page *******************************
@routes_blueprint.route('/return_device/<int:device_id>', methods=['POST'])
@login_required
def return_device(device_id):
    device = db.get_or_404(Device, device_id)
    patron_id = device.assigned_to_id
    device.return_at = datetime.now(timezone.utc)
    db.session.commit()
    flash('Return date set successfully.', 'success')
    return redirect(url_for('routes.patron_details', patron_id=patron_id))


# ****************** Bulk Upload Devices Page *******************************
@routes_blueprint.route('/bulk_upload_devices', methods=['GET', 'POST'])
@login_required
def bulk_upload_devices():
    # Ensure only admins can access this route
    if not (current_user.is_admin or current_user.is_tech_role):
        abort(403)

    if request.method == 'GET':
        return render_template('bulk_upload_devices.html',
                               current_page_name='Bulk Upload Devices',
                               current_path=request.path)

    if 'csvFile' not in request.files:
        flash('No file part.', 'danger')
        return render_template('bulk_upload_devices.html',
                               current_page_name='Bulk Upload Devices',
                               current_path=request.path)

    file = request.files['csvFile']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return render_template('bulk_upload_devices.html',
                               current_page_name='Bulk Upload Devices',
                               current_path=request.path)

    if not file.filename.endswith('.csv'):
        flash('Invalid file format. Please upload a CSV file.', 'danger')
        return render_template('bulk_upload_devices.html',
                               current_page_name='Bulk Upload Devices',
                               current_path=request.path)

    VALID_CONDITIONS = {'New', 'Used', 'Broken Screen', 'Damaged Keyboard', 'Not Charging', 'Water Damaged', 'Not Turning On', 'Other'}
    errors = []
    devices_added = 0
    devices_updated = 0

    try:
        stream = file.stream.read().decode('UTF-8')
        csv_reader = csv.DictReader(stream.splitlines())

        for row_num, row in enumerate(csv_reader, start=2):
            row_errors = []

            # Validate required fields
            required_fields = ['category_name', 'serial_num', 'brand_name', 'model_name', 'device_condition', 'site_name']
            missing = [f for f in required_fields if not row.get(f, '').strip()]
            if missing:
                row_errors.append(f"Missing required fields: {', '.join(missing)}")
                errors.append({'row': row_num, 'serial': row.get('serial_num', 'N/A'), 'reasons': row_errors})
                continue

            # Lookup category
            category = Category.query.filter_by(category_name=row['category_name'].strip()).first()
            if not category:
                row_errors.append(f"Category '{row['category_name'].strip()}' not found.")

            # Lookup site
            site = _find_site(row['site_name'])
            if not site:
                row_errors.append(f"Site '{row['site_name'].strip()}' not found.")

            # Validate condition
            condition = row['device_condition'].strip().lower()
            if condition not in VALID_CONDITIONS:
                row_errors.append(f"Invalid condition '{row['device_condition'].strip()}'. Must be one of: {', '.join(VALID_CONDITIONS)}.")

            # Lookup patron by badge_id (optional)
            patron_id = None
            if row.get('badge_id', '').strip():
                patron = Patron.query.filter_by(badge_id=row['badge_id'].strip()).first()
                if not patron:
                    row_errors.append(f"Patron with badge_id '{row['badge_id'].strip()}' not found.")
                else:
                    patron_id = patron.id

            # Parse return_at (optional)
            return_at = None
            if row.get('return_at', '').strip():
                try:
                    return_at = datetime.strptime(row['return_at'].strip(), '%Y-%m-%d')
                except ValueError:
                    row_errors.append("Invalid return_at format. Use YYYY-MM-DD.")

            if row_errors:
                errors.append({'row': row_num, 'serial': row.get('serial_num', 'N/A'), 'reasons': row_errors})
                continue

            serial = row['serial_num'].strip()
            existing_device = Device.query.filter_by(serial_num=serial).first()
            if existing_device:
                existing_device.category_id = category.id
                existing_device.brand_name = row['brand_name'].strip().title()
                existing_device.model_name = row['model_name'].strip().title()
                existing_device.device_condition = condition
                existing_device.site_id = site.id
                existing_device.device_tag = row.get('device_tag', '').strip() or existing_device.device_tag
                existing_device.assigned_to_id = patron_id
                existing_device.return_at = return_at
                existing_device.comments = row.get('comments', '').strip() or existing_device.comments
                existing_device.updated_at = datetime.now(timezone.utc)
                devices_updated += 1
            else:
                new_device = Device(
                    category_id=category.id,
                    serial_num=serial,
                    device_tag=row.get('device_tag', '').strip() or None,
                    brand_name=row['brand_name'].strip().title(),
                    model_name=row['model_name'].strip().title(),
                    device_condition=condition,
                    site_id=site.id,
                    assigned_to_id=patron_id,
                    return_at=return_at,
                    comments=row.get('comments', '').strip() or None,
                    user_id=current_user.id
                )
                db.session.add(new_device)
                devices_added += 1

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Bulk upload devices error: {e}', exc_info=True)
        flash('An error occurred while processing the file. Check server logs for details.', 'danger')
        return render_template('bulk_upload_devices.html',
                               current_page_name='Bulk Upload Devices',
                               current_path=request.path)

    return render_template('bulk_upload_devices.html',
                           current_page_name='Bulk Upload Devices',
                           current_path=request.path,
                           processed=True,
                           devices_added=devices_added,
                           devices_updated=devices_updated,
                           errors=errors)


# ****************** Delete Patron Page *******************************
@routes_blueprint.route('/delete_patron/<int:patron_id>', methods=['POST'])
@login_required
def delete_patron(patron_id):
    is_admin()  # Ensure only admins can access this route
    patron = db.get_or_404(Patron, patron_id)
    db.session.delete(patron)
    db.session.commit()
    flash('Patron deleted successfully!', 'warning')
    return redirect(url_for('routes.patrons'))