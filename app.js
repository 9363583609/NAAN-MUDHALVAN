import boto3
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from boto3.dynamodb.conditions import Key
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Used for session management


login_manager = LoginManager()
login_manager.init_app(app)


cognito_client = boto3.client('cognito-idp', region_name='us-east-1')  # Update region if needed
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
sns_client = boto3.client('sns', region_name='us-east-1')


blood_requests_table = dynamodb.Table('BloodRequests')
inventory_table = dynamodb.Table('BloodInventory')


SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:BloodRequestsTopic'


COGNITO_USER_POOL_ID = 'us-east-1_XXXXXXX'
COGNITO_CLIENT_ID = 'XXXXXXXXXXXXXX'


class User:
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    # Retrieve the user from Cognito using user_id (this can be changed based on your setup)
    response = cognito_client.admin_get_user(
        UserPoolId=COGNITO_USER_POOL_ID,
        Username=user_id
    )
    user_data = response['UserAttributes']
    return User(user_id, user_data[0]['Value'], 'admin' if user_data else 'donor')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        
        try:
            response = cognito_client.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                ClientId=COGNITO_CLIENT_ID,
                AuthParameters={'USERNAME': username, 'PASSWORD': password}
            )
            id_token = response['AuthenticationResult']['IdToken']
            session['id_token'] = id_token  # Store token in session

           
            user = User(username, username, 'admin')
            login_user(user)

            return redirect(url_for('dashboard'))
        except cognito_client.exceptions.NotAuthorizedException:
            return "Invalid credentials", 403

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    
    blood_requests = blood_requests_table.scan()
    inventory = inventory_table.scan()

    return render_template('dashboard.html', requests=blood_requests['Items'], inventory=inventory['Items'])

@app.route('/submit_blood_request', methods=['POST'])
@login_required
def submit_blood_request():
    blood_type = request.form['blood_type']
    quantity = int(request.form['quantity'])
    urgency = request.form['urgency']

   
    request_id = str(uuid.uuid4())

    
    blood_requests_table.put_item(
        Item={
            'RequestID': request_id,
            'BloodType': blood_type,
            'Quantity': quantity,
            'Urgency': urgency
        }
    )

    
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=f"Urgent blood request: {blood_type} ({quantity} units). Urgency: {urgency}",
        Subject='Urgent Blood Request'
    )

    return redirect(url_for('dashboard'))

@app.route('/update_inventory', methods=['POST'])
@login_required
def update_inventory():
    blood_type = request.form['blood_type']
    quantity = int(request.form['quantity'])

   
    inventory_table.update_item(
        Key={'BloodType': blood_type},
        UpdateExpression='SET Quantity = :quantity',
        ExpressionAttributeValues={':quantity': quantity}
    )

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
