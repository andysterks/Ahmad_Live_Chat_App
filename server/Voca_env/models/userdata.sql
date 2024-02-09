class User(db.Model):
    __tablename__ = "userdata"
    
    id = db.Column(db.Integer, primary_key=True, server_default=db.text("nextval('newtbl_id_seq'::regclass)"))
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    birthdate = db.Column(db.Date, nullable=False)
