from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

# --- CONFIGURACIÓN ---
app.config['SECRET_KEY'] = 'clave_super_secreta_12345' # [VULN: Secreto hardcodeado]
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELOS ---

class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='student') 
    notas = db.relationship('Calificacion', backref='estudiante', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Calificacion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    materia = db.Column(db.String(50), nullable=False)
    nota = db.Column(db.Integer, nullable=False)
    # Nuevo campo para comentarios (Donde haremos la inyección XSS)
    comentario = db.Column(db.String(200), nullable=True)
    student_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))

# --- RUTAS ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # [VULN: Falta CSRF]
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Usuario.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña inválidos')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/agregar_nota', methods=['GET', 'POST'])
@login_required
def agregar_nota():
    if current_user.role != 'teacher':
        return "ACCESO DENEGADO: Solo profesores."

    if request.method == 'POST':
        student_username = request.form.get('student_username')
        materia = request.form.get('materia')
        nota_str = request.form.get('nota')
        comentario = request.form.get('comentario') # Capturamos el comentario

        # ✅ Input Validation (Nota numérica)
        try:
            nota = int(nota_str)
            if nota < 0 or nota > 100:
                flash("Error: La nota debe estar entre 0 y 100.")
                return redirect(url_for('agregar_nota'))
        except ValueError:
            flash("Error: La nota debe ser un número entero.")
            return redirect(url_for('agregar_nota'))

        student = Usuario.query.filter_by(username=student_username).first()
        if not student:
            flash("Error: El estudiante no existe.")
            return redirect(url_for('agregar_nota'))

        # Guardamos el comentario TAL CUAL viene (sin limpiar)
        nueva_nota = Calificacion(materia=materia, nota=nota, comentario=comentario, student_id=student.id)
        db.session.add(nueva_nota)
        db.session.commit()
        flash(f"Nota y comentario agregados a {student_username}.")

    return render_template('agregar_nota.html')

@app.route('/ver_notas')
@login_required
def ver_notas():
    # [VULN: IDOR]
    user_id = request.args.get('id')
    if not user_id:
        user_id = current_user.id
    
    notas = Calificacion.query.filter_by(student_id=user_id).all()
    alumno = db.session.get(Usuario, int(user_id))
    
    return render_template('ver_notas.html', notas=notas, alumno=alumno)

@app.route('/setup')
def setup_db():
    with app.app_context():
        db.create_all()
        if not Usuario.query.filter_by(username='admin').first():
            profe = Usuario(username='admin', role='teacher')
            profe.set_password('admin123')
            db.session.add(profe)
            
            pepe = Usuario(username='pepe', role='student')
            pepe.set_password('pepe123')
            db.session.add(pepe)
            
            juan = Usuario(username='juan', role='student')
            juan.set_password('juan123')
            db.session.add(juan)
            
            db.session.commit()
            
            # Datos de ejemplo
            nota1 = Calificacion(materia='Matematicas', nota=85, comentario='Buen trabajo', student_id=pepe.id)
            nota2 = Calificacion(materia='Historia', nota=90, comentario='Excelente ensayo', student_id=juan.id)
            db.session.add_all([nota1, nota2])
            db.session.commit()
            
            return "BD Reiniciada con soporte para Comentarios XSS."
            
    return "La base de datos ya existe."

if __name__ == '__main__':
    app.run(debug=True)