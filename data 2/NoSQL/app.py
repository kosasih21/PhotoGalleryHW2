#!flask/bin/python
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, DYNAMODB_TABLE
from flask import Flask, jsonify, abort, request, make_response, url_for
from flask import render_template, redirect
import time
import exifread
import json
import uuid
import boto3  
from boto3.dynamodb.conditions import Key, Attr
import pymysql.cursors
from datetime import datetime
import pytz

from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import jwt
from datetime import datetime, timedelta
from urllib.parse import urlparse


"""
    INSERT NEW LIBRARIES HERE (IF NEEDED)
"""

serializer = URLSafeTimedSerializer("your-secret-key")




"""
"""

app = Flask(__name__, static_url_path="")

dynamodb = boto3.resource('dynamodb', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                            region_name=AWS_REGION)

table = dynamodb.Table(DYNAMODB_TABLE)
userTable = dynamodb.Table('PhotoGalleryUser')

UPLOAD_FOLDER = os.path.join(app.root_path,'static','media')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def getExifData(path_name):
    f = open(path_name, 'rb')
    tags = exifread.process_file(f)
    ExifData={}
    for tag in tags.keys():
        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
            key="%s"%(tag)
            val="%s"%(tags[tag])
            ExifData[key]=val
    return ExifData

def s3uploading(filename, filenameWithPath, uploadType="photos"):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
                       
    bucket = PHOTOGALLERY_S3_BUCKET_NAME
    path_filename = uploadType + "/" + filename

    s3.upload_file(filenameWithPath, bucket, path_filename)  
    s3.put_object_acl(ACL='public-read', Bucket=bucket, Key=path_filename)
    return f'''http://{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/{path_filename}'''


"""
    INSERT YOUR NEW FUNCTION HERE (IF NEEDED)
"""

def send_email(email, body):
    try:
        ses = boto3.client(
            'ses',
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )
        response = ses.send_email(
            Source="vkosasih3@gatech.edu",
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': 'Photo Gallery: Confirm Your Account'},
                'Body': {'Text': {'Data': body}}
            }
        )
        print("Email sent! Message ID:", response['MessageId'])
        return True
    except ClientError as e:
        print(f"Error sending email: {e.response['Error']['Message']}")
        return False


def get_logged_in_user():
    token = request.cookies.get('jwtlogin')
    if not token:
        return None

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("userId")
        if not user_id:
            return None
        
        # Retrieve user from DynamoDB
        user_response = userTable.get_item(Key={'userId': user_id})
        if 'Item' in user_response:
            return user_response['Item']
    except jwt.ExpiredSignatureError:
        print("JWT expired")
        return None
    except jwt.exceptions.PyJWTError:
        print("Invalid JWT")
        return None

    return None



"""
"""

"""
    INSERT YOUR NEW ROUTE HERE (IF NEEDED)
"""

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template("signup.html")

    data = request.form
    email = data.get("email")
    first_name = data.get("firstName")
    last_name = data.get("lastName")
    password = data.get("password")

    # Check if user already exists
    response = userTable.scan(
        FilterExpression=Attr('email').eq(email)
    )

    if response.get('Items'):
        return render_template("signup.html", message="User already exists")

    # Generate userId and hash password
    user_id = str(uuid.uuid4())
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Insert user into DynamoDB
    userTable.put_item(
        Item={
            'userId': user_id,
            'email': email,
            'firstName': first_name,
            'lastName': last_name,
            'passwordHash': password_hash,
            'confirmed': False,
            'createdAt': datetime.utcnow().isoformat()
        }
    )

    # Generate confirmation token
    token = serializer.dumps(email, salt="email-confirmation")
    confirm_url = f"http://54.82.239.95:5001/confirm/{token}"

    # Send confirmation email using AWS SES
    email_body = f"Click here to verify your email: {confirm_url}"
    send_email(email, email_body)
    
    # Log to confirm email sent
    print(f"Confirmation email sent to {email}")

    # Display success message in signup page
    return render_template("signup.html", message="A confirmation email has been sent to your email address. Please check your inbox.")

@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = serializer.loads(token, salt="email-confirmation", max_age=3600)
    except Exception as e:
        print(f"Token error: {e}")
        return render_template('confirm.html', message="Invalid or expired token")

    # Check user in DynamoDB
    response = userTable.query(
        IndexName='email-index',
        KeyConditionExpression=Key('email').eq(email)
    )

    if not response.get('Items'):
        return render_template('confirm.html', message="User not found")

    user = response['Items'][0]

    # Update confirmed status
    userTable.update_item(
        Key={'userId': user['userId']},
        UpdateExpression="SET confirmed = :confirmed",
        ExpressionAttributeValues={':confirmed': True}
    )

    print(f"Email confirmed for {email}")

    return redirect(url_for('login', message="Your email has been successfully confirmed. Please log in."))


SECRET_KEY = "your-jwt-secret"

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = request.args.get('message')

    if request.method == 'GET':
        return render_template("login.html", message=message)

    data = request.form
    email = data.get("email")
    password = data.get("password")

    response = userTable.query(
        IndexName='email-index',
        KeyConditionExpression=Key('email').eq(email)
    )

    if not response.get('Items'):
        return render_template("login.html", message="User not found")

    user = response['Items'][0]

    # Check if user is confirmed
    if not user.get('confirmed'):
        return render_template("login.html", message="User not confirmed")

    # Check password hash
    if bcrypt.checkpw(password.encode('utf-8'), user['passwordHash'].encode('utf-8')):
        token = jwt.encode(
            {"userId": user['userId'], "exp": datetime.utcnow() + timedelta(days=1)},
            SECRET_KEY,
            algorithm="HS256"
        )
        response = make_response(redirect(url_for('home_page')))
        response.set_cookie("jwtlogin", token, httponly=True, samesite='Strict')
        return response
    else:
        return render_template("login.html", message="Invalid credentials")

    

@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(redirect(url_for('home_page')))
    response.set_cookie("jwtlogin", "", expires=0)
    return response


@app.route('/album/<string:albumID>/photo/<string:photoID>/delete', methods=['POST'])
def delete_photo(albumID, photoID):
    if not get_logged_in_user():
        return redirect(url_for('login', message="You need to log in to perform this action."))

    
    token = request.cookies.get('jwtlogin')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userId"]
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    response = table.query(
        KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq(photoID)
    )
    photo = response.get('Items', [])[0] if response.get('Items') else None

    if not photo:
        print(f"Photo with ID {photoID} not found in album {albumID}")
        return redirect(url_for('view_photos', albumID=albumID))

    if 'photoURL' in photo:
        photoURL = photo['photoURL']

        parsed_url = urlparse(photoURL)
        s3_key = parsed_url.path.lstrip('/')

        try:
            s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
            s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
            print(f"Deleted photo from S3: {s3_key}")
        except Exception as e:
            print(f"Error deleting S3 object: {e}")

    table.delete_item(
        Key={
            'albumID': albumID,
            'photoID': photoID
        }
    )
    print(f"Deleted photo {photoID} from album {albumID}")

    return redirect(url_for('view_photos', albumID=albumID))



@app.route('/album/<string:albumID>/delete', methods=['POST'])
def delete_album(albumID):
    if not get_logged_in_user():
        return redirect(url_for('login', message="You need to log in to perform this action."))
    
    token = request.cookies.get('jwtlogin')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userId"]
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    album_response = table.query(
        KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail')
    )
    album = album_response.get('Items', [])[0] if album_response.get('Items') else None

    if not album:
        print(f"Album {albumID} not found")
        return redirect(url_for('home_page'))

    photo_response = table.scan(
        FilterExpression=Attr('albumID').eq(albumID) & Attr('photoID').ne('thumbnail')
    )
    photos = photo_response.get('Items', [])

    for photo in photos:
        if 'photoURL' in photo:
            photoURL = photo['photoURL']

            parsed_url = urlparse(photoURL)
            s3_key = parsed_url.path.lstrip('/')

        try:
            s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
            s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
            print(f"Deleted photo from S3: {s3_key}")
        except Exception as e:
            print(f"Error deleting S3 object: {e}")

        table.delete_item(
            Key={
                'albumID': photo['albumID'],
                'photoID': photo['photoID']
            }
        )
        print(f"Deleted photo {photo['photoID']} from album {albumID}")

    table.delete_item(
        Key={
            'albumID': albumID,
            'photoID': 'thumbnail'
        }
    )
    print(f"Deleted album {albumID}")


    return redirect(url_for('home_page'))



@app.route('/delete-account', methods=['POST'])
def delete_account():
    token = request.cookies.get('jwtlogin')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userId"]
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    # if user created albums, delete all photos in those albums
    album_response = table.scan(
        FilterExpression=Attr('userId').eq(user_id) & Attr('photoID').eq('thumbnail')
    )
    albums = album_response.get('Items', [])

    for album in albums:
        album_id = album['albumID']

        photo_response = table.scan(
            FilterExpression=Attr('albumID').eq(album_id) & Attr('photoID').ne('thumbnail')
        )
        photos = photo_response.get('Items', [])

        for photo in photos:
            # delete from S3
            if 'photoURL' in photo:
                photoURL = photo['photoURL']

                parsed_url = urlparse(photoURL)
                s3_key = parsed_url.path.lstrip('/')

            try:
                s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
                s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
                print(f"Deleted photo from S3: {s3_key}")
            except Exception as e:
                print(f"Error deleting S3 object: {e}")

            # delete from dynamo
            table.delete_item(
                Key={
                    'albumID': photo['albumID'],
                    'photoID': photo['photoID']
                }
            )
            print(f"Deleted photo {photo['photoID']} from album {album_id}")

        # delete album
        table.delete_item(
            Key={
                'albumID': album_id,
                'photoID': 'thumbnail'
            }
        )
        print(f"Deleted album {album_id}")

    
    # search for individual photos uploaded by user
    photo_response = table.scan(
        FilterExpression=Attr('uploaderId').eq(user_id) & Attr('photoID').ne('thumbnail')
    )
    photos = photo_response.get('Items', [])

    for photo in photos:
        
        if 'photoURL' in photo:
                photoURL = photo['photoURL']

                parsed_url = urlparse(photoURL)
                s3_key = parsed_url.path.lstrip('/')

        try:
            s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
            s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
            print(f"Deleted photo from S3: {s3_key}")
        except Exception as e:
            print(f"Error deleting S3 object: {e}")

        table.delete_item(
            Key={
                'albumID': photo['albumID'],
                'photoID': photo['photoID']
            }
        )
        print(f"Deleted photo {photo['photoID']} from album {photo['albumID']}")




    # delete user
    userTable.delete_item(
        Key={'userId': user_id}
    )
    print(f"Deleted user {user_id}")

    response = make_response(redirect(url_for('home_page')))
    response.set_cookie("jwtlogin", "", expires=0)
    return response




"""
"""

@app.errorhandler(400)
def bad_request(error):
    """ 400 page route.

    get:
        description: Endpoint to return a bad request 400 page.
        responses: Returns 400 object.
    """
    return make_response(jsonify({'error': 'Bad request'}), 400)



@app.errorhandler(404)
def not_found(error):
    """ 404 page route.

    get:
        description: Endpoint to return a not found 404 page.
        responses: Returns 404 object.
    """
    return make_response(jsonify({'error': 'Not found'}), 404)



@app.route('/', methods=['GET'])
def home_page():
    """ Home page route. """

    user_name = None
    token = request.cookies.get('jwtlogin')

    if token:
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded["userId"]

            # Query the user table to get firstName
            response = userTable.get_item(Key={'userId': user_id})
            if 'Item' in response:
                user_name = response['Item']['firstName']

        except jwt.ExpiredSignatureError:
            print("JWT expired")
        except jwt.exceptions.PyJWTError:
            print("Invalid JWT")

    response = table.scan(FilterExpression=Attr('photoID').eq("thumbnail"))
    results = response['Items']

    if len(results) > 0:
        for index, value in enumerate(results):
            createdAt = datetime.strptime(str(results[index]['createdAt']), "%Y-%m-%d %H:%M:%S")
            createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
            results[index]['createdAt'] = createdAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")

    # Pass user_name to template
    return render_template('index.html', albums=results, user_name=user_name)




@app.route('/createAlbum', methods=['GET', 'POST'])
def add_album():
    token = request.cookies.get('jwtlogin')
    if not get_logged_in_user():
        return redirect(url_for('login', message="You need to log in to perform this action."))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userId"]
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['imagefile']
        name = request.form['name']
        description = request.form['description']

        if file and allowed_file(file.filename):
            albumID = str(uuid.uuid4())
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)

            uploadedFileURL = s3uploading(str(albumID), filenameWithPath, "thumbnails")

            createdAtlocalTime = datetime.now().astimezone()
            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)

            # get username
            user_response = userTable.get_item(Key={'userId': user_id})
            creator = user_response['Item']['firstName'] if 'Item' in user_response else 'Unknown'

            table.put_item(
                Item={
                    "albumID": albumID,
                    "photoID": "thumbnail",
                    "name": name,
                    "description": description,
                    "thumbnailURL": uploadedFileURL,
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "userId": user_id,
                    "creator": creator
                }
            )

        return redirect('/')
    else:
        return render_template('albumForm.html')




@app.route('/album/<string:albumID>', methods=['GET'])
def view_photos(albumID):
    albumResponse = table.query(
        KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail')
    )
    albumMeta = albumResponse['Items']

    if not albumMeta:
        return render_template('viewphotos.html', photos=[], albumID=albumID, albumName="Unknown")

    albumName = albumMeta[0].get('name', 'Unknown')
    creator = albumMeta[0].get('creator', 'Unknown')

    response = table.scan(
        FilterExpression=Attr('albumID').eq(albumID) & Attr('photoID').ne('thumbnail')
    )
    items = response['Items']

    for item in items:
        uploader_id = item.get('uploaderId')
        if uploader_id:
            user_response = userTable.query(
                KeyConditionExpression=Key('userId').eq(uploader_id)
            )
            if user_response.get('Items'):
                item['uploader'] = user_response['Items'][0]['firstName']

    return render_template(
        'viewphotos.html',
        photos=items,
        albumID=albumID,
        albumName=albumName,
        creator=creator
    )





@app.route('/album/<string:albumID>/addPhoto', methods=['GET', 'POST'])
def add_photo(albumID):
    token = request.cookies.get('jwtlogin')
    if not get_logged_in_user():
        return redirect(url_for('login', message="You need to log in to perform this action."))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userId"]
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    if request.method == 'POST':    
        uploadedFileURL=''
        file = request.files['imagefile']
        title = request.form['title']
        description = request.form['description']
        tags = request.form['tags']
        
        if file and allowed_file(file.filename):
            photoID = str(uuid.uuid4())
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)            
            
            uploadedFileURL = s3uploading(filename, filenameWithPath)
            ExifData = getExifData(filenameWithPath)
            ExifDataStr = json.dumps(ExifData)

            createdAtlocalTime = datetime.now().astimezone()
            updatedAtlocalTime = datetime.now().astimezone()

            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)
            updatedAtUTCTime = updatedAtlocalTime.astimezone(pytz.utc)

            table.put_item(
                Item={
                    "albumID": albumID,
                    "photoID": photoID,
                    "title": title,
                    "description": description,
                    "tags": tags,
                    "photoURL": uploadedFileURL,
                    "EXIF": ExifDataStr,
                    "uploaderId": user_id, # Save uploader ID
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "updatedAt": updatedAtUTCTime.strftime("%Y-%m-%d %H:%M:%S")
                }
            )

        return redirect(f'/album/{albumID}')
    else:
        albumResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
        albumMeta = albumResponse['Items']
        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])




@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET'])
def view_photo(albumID, photoID):
    albumResponse = table.query(
        KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail')
    )
    albumMeta = albumResponse['Items']

    response = table.query(
        KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq(photoID)
    )
    results = response['Items']

    if len(results) > 0:
        photo = results[0]
        uploader_id = photo.get('uploaderId')

        if uploader_id:
            user_response = userTable.query(
                KeyConditionExpression=Key('userId').eq(uploader_id)
            )
            if user_response.get('Items'):
                photo['uploader'] = user_response['Items'][0]['firstName']

        photo['EXIF'] = json.loads(photo['EXIF'])
        createdAt = datetime.strptime(str(photo['createdAt']), "%Y-%m-%d %H:%M:%S")
        updatedAt = datetime.strptime(str(photo['updatedAt']), "%Y-%m-%d %H:%M:%S")
        photo['createdAt'] = createdAt.strftime("%B %d, %Y")
        photo['updatedAt'] = updatedAt.strftime("%B %d, %Y")

        tags = photo['tags'].split(',')
        exifdata = photo['EXIF']

        return render_template('photodetail.html', photo=photo, tags=tags, exifdata=exifdata)




@app.route('/album/search', methods=['GET'])
def search_album_page():
    """ search album page route.

    get:
        description: Endpoint to return all the matching albums.
        responses: Returns all the albums based on a particular query.
    """ 
    query = request.args.get('query', None)    

    response = table.scan(FilterExpression=Attr('name').contains(query) | Attr('description').contains(query))
    results = response['Items']

    items=[]
    for item in results:
        if item['photoID'] == 'thumbnail':
            album={}
            album['albumID'] = item['albumID']
            album['name'] = item['name']
            album['description'] = item['description']
            album['thumbnailURL'] = item['thumbnailURL']
            items.append(album)

    return render_template('searchAlbum.html', albums=items, searchquery=query)



@app.route('/album/<string:albumID>/search', methods=['GET'])
def search_photo_page(albumID):
    """ search photo page route.

    get:
        description: Endpoint to return all the matching photos.
        responses: Returns all the photos from an album based on a particular query.
    """ 
    query = request.args.get('query', None)    

    response = table.scan(FilterExpression=Attr('title').contains(query) | Attr('description').contains(query) | Attr('tags').contains(query) | Attr('EXIF').contains(query))
    results = response['Items']

    items=[]
    for item in results:
        if item['photoID'] != 'thumbnail' and item['albumID'] == albumID:
            photo={}
            photo['photoID'] = item['photoID']
            photo['albumID'] = item['albumID']
            photo['title'] = item['title']
            photo['description'] = item['description']
            photo['photoURL'] = item['photoURL']
            items.append(photo)

    return render_template('searchPhoto.html', photos=items, searchquery=query, albumID=albumID)



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)
