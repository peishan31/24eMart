import os, stripe, json
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from .forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from .db_models import db, User, Item
from itsdangerous import URLSafeTimedSerializer
from .funcs import mail, send_confirmation_email, fulfill_order
from dotenv import load_dotenv
from .admin.routes import admin
import pymysql
import boto3
import uuid
from botocore.config import Config

	
load_dotenv()
app = Flask(__name__)
app.register_blueprint(admin)

# app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ["DB_URI"]
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['MAIL_USERNAME'] = os.environ["EMAIL"]
# app.config['MAIL_PASSWORD'] = os.environ["PASSWORD"]
# app.config['MAIL_SERVER'] = "smtp.googlemail.com"
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_PORT'] = 587
# stripe.api_key = os.environ["STRIPE_PRIVATE"]
# TODO: set up environment variables in the future
#


app.config["SECRET_KEY"] = "123" # TODO: research on what this secret key is for

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:12345678@rds-mysql-db.csxucthsan5l.ap-southeast-1.rds.amazonaws.com:3306/rds24emart'
#app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///test.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_USERNAME'] = "randomemail@gmail.com" # not functional; TODO: create a dummy email
app.config['MAIL_PASSWORD'] = "123456" # not functional; TODO: create a dummy email
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_PORT'] = 587
stripe.api_key = "sk_test_51MpZMRJRBOlt2OzTF2WW4p0GBJgEH3pZGmM2lrUejwjjQ0w3B2BeynxsWQbYVOIss5Nd8sexCy2NwQsLH7bZIxzW00ffqyZDP1" # TODO: set up stripe account


db.init_app(app)
Bootstrap(app)
mail.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

with app.app_context():
	db.create_all()

@app.context_processor
def inject_now():
	""" sends datetime to templates as 'now' """
	return {'now': datetime.utcnow()}

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(user_id)

S3_BUCKET = 'elasticbeanstalk-ap-southeast-1-645583429901'	
AWS_ACCESS_KEY_ID = 'AKIAZMT6FMEG2AH5MEF2'
AWS_SECRET_ACCESS_KEY = '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'
#s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
S3_REGION = 'ap-southeast-1'
S3_config = Config(signature_version='s3v4')

@app.route("/")
def home():

	# s3 = boto3.client('s3')
	s3_client = boto3.client('s3', region_name= "eu-central-1", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, config=S3_config)
    # return render_template("index.html", **context)
	preassigned_urls = []
	
	objects = s3_client.list_objects_v2(Bucket=S3_BUCKET)
	image_urls = []
	for obj in objects['Contents']:
		if obj['Key'].endswith('.jpg') or obj['Key'].endswith('.png'):
			url = s3_client.generate_presigned_url(
				'get_object',
				Params={'Bucket': 'my-bucket-name', 'Key': obj['Key']},
				ExpiresIn=3600
			)
			image_urls.append(url)

	print("*****image_urls", image_urls)
	return render_template("home.html", preassigned_urls=image_urls)

	# items = Item.query.all()
	
	# for item in items:
	# 	context = {"s3": s3, "bucket": S3_BUCKET, "key": "503536a8-3047-4ff8-aaab-241df9a4d8757"}
	# 	preassigned_urls.append(context)
	# return render_template("home.html", items=items, preassigned_urls=preassigned_urls)
# import boto3

# @app.route('/list_images')
# def list_images():
#     # Create an S3 client
#     s3 = boto3.client('s3')

#     # Get a list of objects in the bucket
#     objects = s3.list_objects_v2(Bucket='my-bucket-name')

#     # Generate pre-signed URLs for each image file
#     image_urls = []
#     for obj in objects['Contents']:
#         if obj['Key'].endswith('.jpg') or obj['Key'].endswith('.png'):
#             url = s3.generate_presigned_url(
#                 'get_object',
#                 Params={'Bucket': 'my-bucket-name', 'Key': obj['Key']},
#                 ExpiresIn=3600
#             )
#             image_urls.append(url)

#     # Pass the list of pre-signed URLs to the template
#     return render_template('list_images.html', image_urls=image_urls)

@app.route("/login", methods=['POST', 'GET'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = LoginForm()
	if form.validate_on_submit():
		email = form.email.data
		user = User.query.filter_by(email=email).first()
		if user == None:
			flash(f'User with email {email} doesn\'t exist!<br> <a href={url_for("register")}>Register now!</a>', 'error')
			return redirect(url_for('login'))
		elif check_password_hash(user.password, form.password.data):
			login_user(user)
			return redirect(url_for('home'))
		else:
			flash("Email and password incorrect!!", "error")
			return redirect(url_for('login'))
	return render_template("login.html", form=form)

@app.route("/register", methods=['POST', 'GET'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = RegisterForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user:
			flash(f"User with email {user.email} already exists!!<br> <a href={url_for('login')}>Login now!</a>", "error")
			return redirect(url_for('register'))
		new_user = User(name=form.name.data,
						email=form.email.data,
						password=generate_password_hash(
									form.password.data,
									method='pbkdf2:sha256',
									salt_length=8),
						phone=form.phone.data)
		db.session.add(new_user)
		db.session.commit()
		# send_confirmation_email(new_user.email)
		flash('Thanks for registering! You may login now.', 'success')
		return redirect(url_for('login'))
	return render_template("register.html", form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
	try:
		confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
		email = confirm_serializer.loads(token, salt='email-confirmation-salt', max_age=3600)
	except:
		flash('The confirmation link is invalid or has expired.', 'error')
		return redirect(url_for('login'))
	user = User.query.filter_by(email=email).first()
	if user.email_confirmed:
		flash(f'Account already confirmed. Please login.', 'success')
	else:
		user.email_confirmed = True
		db.session.add(user)
		db.session.commit()
		flash('Email address successfully confirmed!', 'success')
	return redirect(url_for('login'))

@app.route("/logout")
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))

@app.route("/resend")
@login_required
def resend():
	send_confirmation_email(current_user.email)
	logout_user()
	flash('Confirmation email sent successfully.', 'success')
	return redirect(url_for('login'))

@app.route("/add/<id>", methods=['POST'])
def add_to_cart(id):
	if not current_user.is_authenticated:
		flash(f'You must login first!<br> <a href={url_for("login")}>Login now!</a>', 'error')
		return redirect(url_for('login'))

	item = Item.query.get(id)
	if request.method == "POST":
		quantity = request.form["quantity"]
		current_user.add_to_cart(id, quantity)
		flash(f'''{item.name} successfully added to the <a href=cart>cart</a>.<br> <a href={url_for("cart")}>view cart!</a>''','success')
		return redirect(url_for('home'))

@app.route("/cart")
@login_required
def cart():
	price = 0
	price_ids = []
	items = []
	quantity = []
	for cart in current_user.cart:
		items.append(cart.item)
		quantity.append(cart.quantity)
		price_id_dict = {
			"price": cart.item.price_id,
			"quantity": cart.quantity,
			}
		price_ids.append(price_id_dict)
		price += cart.item.price*cart.quantity
	return render_template('cart.html', items=items, price=price, price_ids=price_ids, quantity=quantity)

@app.route('/orders')
@login_required
def orders():
	return render_template('orders.html', orders=current_user.orders)

@app.route("/remove/<id>/<quantity>")
@login_required
def remove(id, quantity):
	current_user.remove_from_cart(id, quantity)
	return redirect(url_for('cart'))

@app.route('/item/<int:id>')
def item(id):
	item = Item.query.get(id)
	return render_template('item.html', item=item)

@app.route('/search')
def search():
	query = request.args['query']
	search = "%{}%".format(query)
	items = Item.query.filter(Item.name.like(search)).all()
	return render_template('home.html', items=items, search=True, query=query)

# stripe stuffs
@app.route('/payment_success')
def payment_success():
	return render_template('success.html')

@app.route('/payment_failure')
def payment_failure():
	return render_template('failure.html')

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
	data = json.loads(request.form['price_ids'].replace("'", '"'))
	try:
		checkout_session = stripe.checkout.Session.create(
			client_reference_id=current_user.id,
			line_items=data,
			payment_method_types=[
			  'card',
			],
			mode='payment',
			success_url=url_for('payment_success', _external=True),
			cancel_url=url_for('payment_failure', _external=True),
		)
	except Exception as e:
		return str(e)
	return redirect(checkout_session.url, code=303)

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():

	if request.content_length > 1024*1024:
		print("Request too big!")
		abort(400)

	payload = request.get_data()
	sig_header = request.environ.get('HTTP_STRIPE_SIGNATURE')
	ENDPOINT_SECRET = "whsec_f2e18d92c3c0e2ffbe8d8ea8a934107e3b1d6c4ad32e172a10121299bb4408eb"
	event = None

	try:
		event = stripe.Webhook.construct_event(
		payload, sig_header, ENDPOINT_SECRET
		)
	except ValueError as e:
		# Invalid payload
		return {}, 400
	except stripe.error.SignatureVerificationError as e:
		# Invalid signature
		return {}, 400

	if event['type'] == 'checkout.session.completed':
		session = event['data']['object']

		# Fulfill the purchase...
		fulfill_order(session)

	# Passed signature verification
	return {}, 200
