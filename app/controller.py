from boto3 import resource
from app import config

AWS_ACCESS_KEY_ID = config.AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY = config.AWS_SECRET_ACCESS_KEY
REGION_NAME = config.REGION_NAME

resource = resource(
   'dynamodb',
   aws_access_key_id     = AWS_ACCESS_KEY_ID,
   aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
   region_name           = REGION_NAME
)

user = resource.Table('User')

def get_user(name):
   response = user.get_item(
      Key = {
         'Name' : name
      },
      AttributesToGet = [
         'Name', 'Credit_card_number', 'Email','Gender','Phone', 'Password']
    )
   return response

def create_user(name, email, phone, password):
   response = user.put_item(
      Item = {
      'Name': name,
      'Credit_card_number': '123-123-123',
      'Email': email,
      'Gender': 'Male',
      'Phone': phone,
      'Password': password
      }
   )