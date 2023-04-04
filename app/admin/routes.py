from flask import Blueprint, render_template, url_for, flash
from werkzeug.utils import redirect
from ..db_models import Order, Item, db
from ..admin.forms import AddItemForm, OrderEditForm
from ..funcs import admin_only
import boto3
import uuid
from botocore.exceptions import NoCredentialsError
import requests
from flask import Flask, make_response

app = Flask(__name__)
admin = Blueprint("admin", __name__, url_prefix="/admin", static_folder="static", template_folder="templates")

S3_BUCKET = '24emart-s3'
AWS_ACCESS_KEY_ID = 'AKIAZMT6FMEG2AH5MEF2'
AWS_SECRET_ACCESS_KEY = 'jbDwEGvCQgp+bNoj5ZR6p0vhTk5YzXDpr7Eakpb3'
s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

# replace 'https://api-gateway-url' with the actual URL of your AWS API Gateway
getDashboardUrl = 'https://vonjfookj7.execute-api.ap-southeast-1.amazonaws.com/test/quicksight'

# make the API call using the requests library
response = requests.get(getDashboardUrl)

# access the response content
dashboardEmbedUrl = response.json()

@admin.route('/')
# @admin_only
def dashboard():
    orders = Order.query.all()
    return render_template("admin/home.html", orders=orders)

@admin.route('/quicksight')
# @admin_only
def quicksight():
    # return redirect(dashboardEmbedUrl)
    # create the response
    response = make_response(render_template("admin/quicksight.html", dashboardEmbedUrl = dashboardEmbedUrl))
    # set the content security policy header
    response.headers['Content-Security-Policy'] = "frame-ancestors 'self' https://ap-southeast-1.quicksight.aws.amazon.com"
    return response
    # return render_template("admin/quicksight.html", dashboardEmbedUrl = dashboardEmbedUrl)

@admin.route('/items')
# @admin_only
def items():
    items = Item.query.all()
    return render_template("admin/items.html", items=items)

@admin.route('/add', methods=['POST', 'GET'])
# @admin_only
def add():
    form = AddItemForm()

    if form.validate_on_submit():
        name = form.name.data
        price = form.price.data
        category = form.category.data
        details = form.details.data

        # Upload image to S3
        image_file = form.image.data
        # image_filename = image_file.filename
        image_key = str(uuid.uuid4()) + form.image.data.filename
        
        try:
            s3.upload_fileobj(image_file, S3_BUCKET, image_key)
            image_url = f"https://{S3_BUCKET}.s3.amazonaws.com/{image_key}"
        except NoCredentialsError:
            print("Credentials not available")
            #image_url = url_for('static', filename=f'uploads/{image_filename}') # ****return error
            flash('An error has occurred. Please try again.','error')
            return {'An error has occurred. Please try again.'}, 400
        except:
            flash('An error has occurred. Please try again.','error')
            return {'An error has occurred. Please try again.'}, 400
        # form.image.data.save('app/static/uploads/' + form.image.data.filename)
        # image = url_for('static', filename=f'uploads/{form.image.data.filename}')
        price_id = form.price_id.data
        item = Item(name=name, price=price, category=category, details=details, image=image_url, price_id=price_id)
        db.session.add(item)
        db.session.commit()
        flash(f'{name} added successfully!','success')
        return redirect(url_for('admin.items'))
    return render_template("admin/add.html", form=form)

@admin.route('/edit/<string:type>/<int:id>', methods=['POST', 'GET'])
# @admin_only
def edit(type, id):
    if type == "item":
        item = Item.query.get(id)
        form = AddItemForm(
            name = item.name,
            price = item.price,
            category = item.category,
            details = item.details,
            image = item.image,
            price_id = item.price_id,
        )
        if form.validate_on_submit():
            item.name = form.name.data
            item.price = form.price.data
            item.category = form.category.data
            item.details = form.details.data
            item.price_id = form.price_id.data
            # form.image.data.save('app/static/uploads/' + form.image.data.filename)
            # item.image = url_for('static', filename=f'uploads/{form.image.data.filename}')
            new_image_file = form.image.data
            new_image_filename = str(uuid.uuid4()) + '.' + new_image_file.filename.split('.')[-1]

            # Delete the old image file from S3 bucket
            old_image_filename = item.image.split('/')[-1]
            try:
                s3.delete_object(Bucket=S3_BUCKET, Key=old_image_filename)
            except NoCredentialsError:
                print("Credentials not available")
                flash('An error has occurred. Please try again.','error')
                return {'An error has occurred. Please try again.'}, 400
            except:
                flash('An error has occurred. Please try again.','error')
                return {'An error has occurred. Please try again.'}, 400
            # Upload the new image file to S3 bucket
            try:
                s3.upload_fileobj(new_image_file, S3_BUCKET, new_image_filename)
                item.image = f"https://{S3_BUCKET}.s3.amazonaws.com/{new_image_filename}"
            except NoCredentialsError:
                print("Credentials not available")
                #item.image = url_for('static', filename=f'uploads/{new_image_filename}')
                flash('An error has occurred. Please try again.','error')
                return {'An error has occurred. Please try again.'}, 400
            except:
                flash('An error has occurred. Please try again.','error')
                return {'An error has occurred. Please try again.'}, 400

            db.session.commit()
            return redirect(url_for('admin.items'))
    elif type == "order":
        order = Order.query.get(id)
        form = OrderEditForm(status = order.status)
        if form.validate_on_submit():
            order.status = form.status.data
            db.session.commit()
            return redirect(url_for('admin.dashboard'))
    return render_template('admin/add.html', form=form)

@admin.route('/delete/<int:id>')
@admin_only
def delete(id):
    to_delete = Item.query.get(id)
    # Delete the image file from S3 bucket
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    image_filename = to_delete.image.split('/')[-1]
    try:
        s3.delete_object(Bucket=S3_BUCKET, Key=image_filename)
    except NoCredentialsError:
        print("Credentials not available")
        flash('An error has occurred. Please try again.','error')
        return {'An error has occurred. Please try again.'}, 400
    except:
        flash('An error has occurred. Please try again.','error')
        return {'An error has occurred. Please try again.'}, 400

    db.session.delete(to_delete)
    db.session.commit()
    flash(f'{to_delete.name} deleted successfully', 'error')
    return redirect(url_for('admin.items'))