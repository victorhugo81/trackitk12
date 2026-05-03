# TrackITK12

![TrackITK12 Logo](https://apps.zavistar.com/wp-content/uploads/2026/05/trackITk12-White-Logo.png) 

TrackITK12 is a web-based device inventory and checkout tracking system designed for K-12 school districts. It helps IT staff manage device assignments, track repairs, monitor availability, and maintain an audit trail of all device activity — built with Flask and Bootstrap 5.

[TrackITK12.com](https://TrackITK12.com) 

![TrackITK12 Logo](https://apps.zavistar.com/wp-content/uploads/2026/05/trackitk12-website.png) 

## Features

- **Device inventory**: Add, edit, and track devices (Chromebooks, laptops, tablets, etc.) by serial number, asset tag, brand, and model.
- **Checkout & return tracking**: Assign devices to patrons (students/staff) and record checkout and return dates.
- **Patron management**: Manage students and staff who borrow devices, with badge ID, grade, site, and guardian info.
- **Repair tracking**: Mark devices as in-repair and log repair notes with timestamped comments.
- **Audit trail**: Every field change on a device is recorded — who changed it, when, and what the old and new values were.
- **Bulk uploads**: Import devices, patrons, users, and sites from CSV files.
- **Site management**: Organize devices and users by school site.
- **Role-based access**: Admin, Specialist, and Technician roles control what users can see and do.
- **Dashboard**: Overview of total devices, checked-out count, available count, in-repair count, and per-site breakdowns.
- **Email notifications**: Configurable email alerts via Flask-Mail (SMTP).
- **FTP export**: Scheduled FTP export of data with configurable days, time, and date range.

## Application Versions

- **Python 3.12.x**
- **Flask 3.1.0**
- **SQLite** (development) / **MySQL** (production)
- See `pyproject.toml` for a complete list of dependencies.

## Installation

### Prerequisites

- [Git](https://git-scm.com/downloads/linux)
- [UV — ultra-fast Python package manager](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer)
- [Python 3.12.x](https://docs.astral.sh/uv/concepts/python-versions/#installing-a-python-version)
- **Development**: SQLite (included with Python — no additional install needed)
- **Production**: [MySQL Server](https://dev.mysql.com/doc/mysql-getting-started/en/)

---

### Step 1: Clone the repository

```bash
git clone https://github.com/victorhugo81/trackitk12
cd trackitk12
```

### Step 2: Set up a virtual environment

**Windows:**
```bash
uv venv .venv
```
```bash
.venv\Scripts\activate
```

**MacOS/Linux:**
```bash
uv venv .venv
```
```bash
source .venv/bin/activate
```

### Step 3: Initialize UV project and install dependencies

```bash
uv sync
```

### Step 4: APP Database Setup

> **Important:** Don't commit your `.env` file to version control. Make sure it's added to `.gitignore` to protect sensitive information.

Run the setup script to generate your `.env` file:

```bash
cd installation
python create_env.py
```

Edit the generated `.env` file with your actual values:

```env
# Flask secret key — use a long random string
SECRET_KEY=your_secure_random_key_here

# MySQL (production)
# DATABASE_URL=mysql+pymysql://username:password@localhost/trackitk12
```

Run the seed script to create tables and populate initial lookup data (roles, categories, organization defaults):

```bash
python seed_data.py
```

### Step 5: Start Flask development server

```bash
cd ..
flask --app main.py run
```

Open your browser and navigate to: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Usage

### Login

Enter your admin email and password.

- Passwords must be at least 10 characters and include letters, numbers, and special characters.
- First-time users prompted with `must_change_password` will be redirected to change their password on login.

![Login Screen](https://apps.zavistar.com/wp-content/uploads/2026/05/trackitk12-login.png)

### Dashboard

The dashboard shows key stats at a glance:

- Total devices, checked-out, available, and in-repair counts
- Per-site device breakdown
- Recent checkout activity

![Dashboard](https://apps.zavistar.com/wp-content/uploads/2026/05/trackitk12-dashboard-scaled.png)

### Devices

- Browse and filter the full device list
- Click a device to view or edit its details
- Assign a device to a patron using the patron search modal
- Mark a device as in-repair and log repair notes
- View the complete audit trail of all field changes

### Checking Out a Device

1. Go to **Devices** and open the device record.
2. Use the patron search to find and select the patron.
3. Save the record — the checkout timestamp is recorded automatically.

### Returning a Device

1. Open the device record.
2. Click **Return Device** — the return timestamp is recorded.

### Patrons

- Add and manage students and staff who borrow devices.
- View all devices currently assigned to a patron on their detail page.
- Use the assign-device modal directly from the patron detail page.

### Bulk Uploads

Admin and tech users can upload CSV files to bulk-import:

- **Devices** — serial number, asset tag, brand, model, category, site
- **Patrons** — badge ID, name, grade, site, guardian info
- **Users** — staff accounts
- **Sites** — school site records

Navigate to the **Bulk Upload** section in the sidebar and download the CSV template for the correct column format.

### Admin Settings

- **Organization**: Set organization name, logo, and email/FTP configuration.
- **Sites**: Manage school sites.
- **Roles**: Define user roles (Admin, Specialist, Technician, etc.).
- **Categories**: Manage device categories (Chromebook, Laptop, iPad, etc.).
- **Notifications**: Configure system-wide notification messages.
- **Users**: Create and manage staff accounts.

---

## Troubleshooting

### Database connection issues

- For SQLite: confirm `DATABASE_URL=sqlite:///app.db` is set in `.env` and the `migrations/` folder is present.
- For MySQL: ensure your MySQL server is running and the credentials in `.env` are correct.

### Migration errors

```bash
flask db upgrade
```

If migrations are out of sync, try:

```bash
flask db stamp head
flask db migrate
flask db upgrade
```

### Missing dependencies

```bash
uv sync
```

---

## Production Deployment

1. Set `DATABASE_URL` to a MySQL connection string in `.env`.
2. Set `SECRET_KEY` to a strong random value — the app will raise an error at startup if it detects the default dev key.
3. Set `FLASK_ENV=production` in your server environment so the app boots with `ProductionConfig`.
4. Install dependencies and start Gunicorn (included in `pyproject.toml`):
   ```bash
   uv sync
   uv run gunicorn -w 4 "main:create_app()"
   ```
5. Set up a reverse proxy with Nginx or Apache.
6. Enable HTTPS — `SESSION_COOKIE_SECURE` is automatically set to `True` in `ProductionConfig`.

---

## Contributing

We welcome contributions!

1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add: description of your changes"
   ```
4. Push and open a pull request:
   ```bash
   git push origin feature/your-feature-name
   ```

---

## Project Structure

```
trackitk12_dev/
├── application/
│   ├── __init__.py
│   ├── models.py          # SQLAlchemy models
│   ├── forms.py           # Flask-WTF forms
│   ├── routes.py          # All app routes (blueprints)
│   ├── utils.py           # Encryption, hashing helpers
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── img/
│   └── templates/
│       ├── includes/
│       │   ├── footer.html
│       │   └── nav.html
│       ├── base.html
│       ├── index.html              # Dashboard
│       ├── login.html
│       ├── devices.html            # Device list
│       ├── add_device.html
│       ├── edit_device.html        # Device detail + repair comments + audit trail
│       ├── patrons.html            # Patron list
│       ├── add_patron.html
│       ├── edit_patron.html
│       ├── patron_details.html     # Patron detail + assigned devices
│       ├── users.html
│       ├── add_user.html
│       ├── edit_user.html
│       ├── change_password.html
│       ├── sites.html
│       ├── add_site.html
│       ├── edit_site.html
│       ├── roles.html
│       ├── add_role.html
│       ├── edit_role.html
│       ├── categories.html
│       ├── add_category.html
│       ├── edit_category.html
│       ├── notifications.html
│       ├── add_notification.html
│       ├── edit_notification.html
│       ├── organization.html
│       ├── profile.html
│       ├── bulk_upload_devices.html
│       ├── bulk_upload_patrons.html
│       ├── bulk_upload_data.html
│       └── error.html
├── installation/
│   ├── create_env.py      # Generates .env file
│   └── seed_data.py       # Seeds initial DB data
├── migrations/            # Alembic migration files
├── tests/
├── main.py                # App entry point
├── config.py              # Dev / Prod / Testing configs
├── requirements.txt
└── pyproject.toml
```

---

## License

TrackITK12 is licensed under the GNU General Public License v3. See the `LICENSE` file for details.

## Contact

For questions or suggestions, open an issue on GitHub or email: contact@victorhugosolis.com

## Disclaimer

TrackITK12 is under active development and may contain bugs or limitations. Feedback and contributions are welcome.
