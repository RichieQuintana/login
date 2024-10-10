from flask import Flask, request, render_template, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = "clave_secreta"

# Configuración de SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Modelo de usuario para inicio de sesión
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Modelo de usuario creado en el dashboard
class UsuarioDashboard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

# Ruta principal
@app.route('/')
def index():
    if "username" in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html")

# Login
@app.route("/login", methods=["POST"])
def login():
    username = request.form['username']
    password = request.form['password']
    user = Usuario.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        return render_template("index.html", error="Credenciales incorrectas")

# Registro
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_template("register.html", error="Las contraseñas no coinciden")
        if Usuario.query.filter_by(email=email).first() or Usuario.query.filter_by(username=username).first():
            return render_template("register.html", error="Usuario o correo ya registrado")
        new_user = Usuario(email=email, username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template("register.html")

# Dashboard
@app.route("/dashboard")
def dashboard():
    if "username" in session:
        users = UsuarioDashboard.query.all()
        return render_template("dashboard.html", username=session['username'], users=users)
    return redirect(url_for('index'))

# Create User
@app.route("/create_user", methods=["POST"])
def create_user():
    if "username" not in session:
        return redirect(url_for('index'))
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    if UsuarioDashboard.query.filter_by(email=email).first() or UsuarioDashboard.query.filter_by(username=username).first():
        flash("Usuario o correo ya registrado", "error")
    else:
        new_user = UsuarioDashboard(email=email, username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("Usuario creado exitosamente", "success")
    return redirect(url_for('dashboard'))

# Edit User
@app.route("/edit_user/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    if "username" not in session:
        return redirect(url_for('index'))
    
    user = UsuarioDashboard.query.get_or_404(user_id)
    user.username = request.form['username']
    user.email = request.form['email']
    if request.form['password']:
        user.set_password(request.form['password'])
    db.session.commit()
    flash("Usuario actualizado exitosamente", "success")
    return redirect(url_for('dashboard'))

# Delete User
@app.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "username" not in session:
        return redirect(url_for('index'))
    
    user = UsuarioDashboard.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("Usuario eliminado exitosamente", "success")
    return redirect(url_for('dashboard'))

# Logout
@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)