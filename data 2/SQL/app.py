#!flask/bin/python
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, RDS_DB_HOSTNAME, RDS_DB_USERNAME, RDS_DB_PASSWORD, RDS_DB_NAME
from flask import Flask, jsonify, abort, request, make_response, url_for
from flask import render_template, redirect
import uuid
from itsdangerous import URLSafeTimedSerializer
import time
import exifread
import json
import uuid
import boto3  
from botocore.exceptions import ClientError
import pymysql.cursors
import bcrypt
from datetime import datetime
from pytz import timezone
import jwt
from datetime import datetime, timedelta


"""
    INSERT NEW LIBRARIES HERE (IF NEEDED)
"""




"""
"""

app = Flask(__name__, static_url_path="")

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

def get_database_connection():
    conn = pymysql.connect(host=RDS_DB_HOSTNAME,
                             user=RDS_DB_USERNAME,
                             password=RDS_DB_PASSWORD,
                             db=RDS_DB_NAME,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)
    return conn

def send_email(email, body):
    try:
        ses = boto3.client(
            'ses',
            aws_access_key_id=AWS_ACCESS_KEY,        # Pass credentials directly
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



"""
    INSERT YOUR NEW FUNCTION HERE (IF NEEDED)
"""

def check_login():
    token = request.cookies.get("jwtlogin_SQL", default=None)
    if not token:
        return None  # User not logged in

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded["userID"]
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.exceptions.PyJWTError:
        return None  # Invalid token




"""
"""

"""
    INSERT YOUR NEW ROUTE HERE (IF NEEDED)
"""

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('home_page')))
    response.set_cookie("jwtlogin_SQL", "", expires=0)
    return response

SECRET_KEY = "your-jwt-secret" # PLEASE CHANGE THIS TO A SECURE KEY

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = request.args.get('message')

    if request.method == 'GET':
        return render_template("login.html", message=message)
    
    data = request.form
    email = data.get("email")
    password = data.get("password")

    connection = pymysql.connect(**DB_CONFIG)
    cursor = connection.cursor()
    cursor.execute("SELECT userID, passwordHash, verified FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        return render_template("login.html", message="User not found")
    
    user_id, password_hash, verified = user
    if not verified:
        return render_template("login.html", message="User not verified")
    
    if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
        response = make_response(redirect(url_for('home_page')))
        token = jwt.encode({"userID": user_id, "exp": datetime.utcnow() + timedelta(days=1)}, SECRET_KEY, algorithm="HS256")
        response.set_cookie("jwtlogin_SQL", token, httponly=True, samesite='Strict')
        return response
    else:
        return render_template("login.html", message="Incorrect password")
    

    
@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = serializer.loads(token, salt="email-confirmation", max_age=3600)
    except:
        return render_template("confirm.html", message="Invalid or expired token")

    connection = get_database_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET verified = TRUE, updatedAt = NOW() WHERE email = %s", (email,))
    connection.commit()
    cursor.close()
    connection.close()

    return render_template("confirm.html", message="Your email has been successfully confirmed. You can now log in.")




# Flask Secret Key for Token Generation
serializer = URLSafeTimedSerializer("your-secret-key")

# RDS MySQL Configuration
DB_CONFIG = {
    "host":RDS_DB_HOSTNAME,
    "user": RDS_DB_USERNAME,
    "password": RDS_DB_PASSWORD,
    "database": RDS_DB_NAME
}

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template("signup.html")

    data = request.form
    email = data.get("email")
    first_name = data.get("firstName")
    last_name = data.get("lastName")
    password = data.get("password")

    connection = pymysql.connect(**DB_CONFIG)
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    if cursor.fetchone():
        print("User already exists")
        return render_template("signup.html", message="User already exists")

    user_id = str(uuid.uuid4())
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cursor.execute("INSERT INTO users (userID, email, firstName, lastName, passwordHash, createdAt) VALUES (%s, %s, %s, %s, %s, NOW())",
                   (user_id, email, first_name, last_name, password_hash))
    connection.commit()
    cursor.close()
    connection.close()

    token = serializer.dumps(email, salt="email-confirmation")
    confirm_url = f"54.82.239.95:5000/confirm/{token}"

    email_body = f"Click here to verify your email: {confirm_url}"
    send_email(email, email_body)
    # log to confirm email sent
    print(f"Confirmation email sent to {email}")

    return render_template("signup.html", message="A confirmation email has been sent to your email address. Please check your inbox.")



@app.route('/album/<string:albumID>/photo/<string:photoID>/delete', methods=['POST'])
def delete_photo(albumID, photoID):
    token = request.cookies.get('jwtlogin_SQL')
    if not token:
        return redirect(url_for('login', message="You need to log in to perform this action."))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userID"]
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    connection = get_database_connection()
    cursor = connection.cursor()

    # First, get the photo URL to delete it from S3
    statement = '''
        SELECT photoURL FROM photogallerydb.Photo
        WHERE photoID = %s AND albumID = %s;
    '''
    cursor.execute(statement, (photoID, albumID))
    result = cursor.fetchone()

    if result:
        photoURL = result['photoURL']
        # Extract the S3 key from the URL
        s3_key = photoURL.split(f"{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/")[1]

        try:
            # Delete the file from S3
            s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                              aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
            s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
            print(f"Deleted photo from S3: {s3_key}")
        except Exception as e:
            print(f"Error deleting from S3: {e}")

        # Delete the photo entry from the RDS database
        statement = '''
            DELETE FROM photogallerydb.Photo
            WHERE photoID = %s AND albumID = %s;
        '''
        cursor.execute(statement, (photoID, albumID))
        connection.commit()

        print(f"Deleted photo {photoID} from database")

    cursor.close()
    connection.close()

    # Redirect back to the album page
    return redirect(url_for('view_photos', albumID=albumID))


@app.route('/album/<string:albumID>/delete', methods=['POST'])
def delete_album(albumID):
    token = request.cookies.get('jwtlogin_SQL')
    if not token:
        return redirect(url_for('login', message="You need to log in to perform this action."))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userID"]
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    connection = get_database_connection()
    cursor = connection.cursor()

    # Get the album thumbnail to delete from S3
    statement = '''
        SELECT thumbnailURL FROM photogallerydb.Album
        WHERE albumID = %s;
    '''
    cursor.execute(statement, (albumID,))
    album = cursor.fetchone()

    if album:
        thumbnailURL = album['thumbnailURL']
        if thumbnailURL:
            # Extract the S3 key from the URL
            s3_key = thumbnailURL.split(f"{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/")[1]
            try:
                s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                                  aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
                s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
                print(f"Deleted album thumbnail from S3: {s3_key}")
            except Exception as e:
                print(f"Error deleting album thumbnail from S3: {e}")

    # Get all photos associated with the album
    statement = '''
        SELECT photoURL FROM photogallerydb.Photo
        WHERE albumID = %s;
    '''
    cursor.execute(statement, (albumID,))
    photos = cursor.fetchall()

    # Delete each photo from S3
    for photo in photos:
        photoURL = photo['photoURL']
        if photoURL:
            s3_key = photoURL.split(f"{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/")[1]
            try:
                s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
                print(f"Deleted photo from S3: {s3_key}")
            except Exception as e:
                print(f"Error deleting photo from S3: {e}")

    # Delete all photo records from the RDS table
    statement = '''
        DELETE FROM photogallerydb.Photo
        WHERE albumID = %s;
    '''
    cursor.execute(statement, (albumID,))
    connection.commit()
    print(f"Deleted all photos from album {albumID}")

    # Finally, delete the album itself
    statement = '''
        DELETE FROM photogallerydb.Album
        WHERE albumID = %s;
    '''
    cursor.execute(statement, (albumID,))
    connection.commit()
    print(f"Deleted album {albumID} from database")

    cursor.close()
    connection.close()

    # Redirect back to the homepage
    return redirect(url_for('home_page'))

@app.route('/delete-account', methods=['POST'])
def delete_account():
    token = request.cookies.get('jwtlogin_SQL')
    if not token:
        return redirect(url_for('login', message="You need to log in to perform this action."))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userID"]
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    connection = get_database_connection()
    cursor = connection.cursor()

    # DELETE ALL PHOTOS UPLOADED BY USER
    statement = '''
        SELECT photoURL FROM photogallerydb.Photo
        WHERE userID = %s;
    '''
    cursor.execute(statement, (user_id,))
    photos = cursor.fetchall()

    for photo in photos:
        photoURL = photo['photoURL']
        if photoURL:
            s3_key = photoURL.split(f"{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/")[1]
            try:
                s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                                  aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
                s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
                print(f"Deleted photo from S3: {s3_key}")
            except Exception as e:
                print(f"Error deleting photo from S3: {e}")

    # DELETE ALL PHOTO RECORDS FROM RDS
    statement = '''
        DELETE FROM photogallerydb.Photo
        WHERE userID = %s;
    '''
    cursor.execute(statement, (user_id,))
    connection.commit()
    print(f"Deleted all photos uploaded by user {user_id}")

    # DELETE ALL ALBUMS CREATED BY USER
    # Get all album thumbnails created by the user
    statement = '''
        SELECT albumID, thumbnailURL FROM photogallerydb.Album
        WHERE userID = %s;
    '''
    cursor.execute(statement, (user_id,))
    albums = cursor.fetchall()

    for album in albums:
        thumbnailURL = album['thumbnailURL']
        if thumbnailURL:
            s3_key = thumbnailURL.split(f"{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/")[1]
            try:
                s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
                print(f"Deleted album thumbnail from S3: {s3_key}")
            except Exception as e:
                print(f"Error deleting album thumbnail from S3: {e}")

    # DELETE ALL ALBUM RECORDS FROM RDS
    statement = '''
        DELETE FROM photogallerydb.Album
        WHERE userID = %s;
    '''
    cursor.execute(statement, (user_id,))
    connection.commit()
    print(f"Deleted all albums created by user {user_id}")

    # STEP 3: DELETE USER ACCOUNT
    statement = '''
        DELETE FROM users
        WHERE userID = %s;
    '''
    cursor.execute(statement, (user_id,))
    connection.commit()
    print(f"Deleted user {user_id}")

    cursor.close()
    connection.close()

    # Clear session cookie and log out
    response = make_response(redirect(url_for('home_page')))
    response.set_cookie("jwtlogin_SQL", "", expires=0)

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
    user_name = None
    token = request.cookies.get('jwtlogin_SQL')
    if token:
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded["userID"]

            connection = get_database_connection()
            cursor = connection.cursor()
            cursor.execute("SELECT firstName FROM users WHERE userID = %s", (user_id,))
            user = cursor.fetchone()
            connection.close()

            if user:
                user_name = user["firstName"]

        except jwt.ExpiredSignatureError:
            print("JWT expired")
        except jwt.exceptions.PyJWTError:
            print("Invalid JWT")

    connection = get_database_connection()
    cursor = connection.cursor()

    # List the columns in the same order as the table structure
    statement = '''
        SELECT a.albumID, a.name, a.description, a.thumbnailURL, a.createdAt, u.firstName AS creator
        FROM photogallerydb.Album a
        INNER JOIN users u ON a.userID = u.userID
    '''
    cursor.execute(statement)
    results = cursor.fetchall()
    connection.close()

    items = []
    for item in results:
        album = {}
        album['albumID'] = item['albumID']
        album['name'] = item['name']
        album['description'] = item['description']
        album['thumbnailURL'] = item['thumbnailURL']
        album['creator'] = item['creator']  # Should now contain data
        
        createdAt = datetime.strptime(str(item['createdAt']), "%Y-%m-%d %H:%M:%S")
        createdAt_UTC = timezone("UTC").localize(createdAt)
        album['createdAt'] = createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")

        items.append(album)

    return render_template('index.html', albums=items, user_name=user_name)







@app.route('/createAlbum', methods=['GET', 'POST'])
def add_album():
    token = request.cookies.get('jwtlogin_SQL')
    if not token:
        return redirect(url_for('login', message="You need to log in to perform this action."))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userID"]
        print(f"Creating album for user: {user_id}")  # Debugging statement
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['imagefile']
        name = request.form['name']
        description = request.form['description']

        if file and allowed_file(file.filename):
            albumID = uuid.uuid4()
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)

            uploadedFileURL = s3uploading(str(albumID), filenameWithPath, "thumbnails")

            connection = get_database_connection()
            cursor = connection.cursor()

            # Fix column order to match the table structure
            statement = '''
                INSERT INTO photogallerydb.Album (albumID, name, description, thumbnailURL, createdAt, userID)
                VALUES (%s, %s, %s, %s, NOW(), %s)
            '''
            cursor.execute(statement, (albumID, name, description, uploadedFileURL, user_id))
            connection.commit()
            connection.close()

            print(f"Album created by user: {user_id}")  # Debugging statement

        return redirect('/')
    else:
        return render_template('albumForm.html')




@app.route('/album/<string:albumID>', methods=['GET'])
def view_photos(albumID):
    """ Album page route. """
    connection = get_database_connection()
    cursor = connection.cursor()

    # Get album details + creator name using a JOIN
    statement = '''
        SELECT a.name, a.description, a.thumbnailURL, a.createdAt, u.firstName AS creator
        FROM photogallerydb.Album a
        INNER JOIN users u ON a.userID = u.userID
        WHERE a.albumID = %s;
    '''
    cursor.execute(statement, (albumID,))
    albumMeta = cursor.fetchone()

    # Get photos + uploader name
    statement = '''
        SELECT p.photoID, p.albumID, p.title, p.description, p.photoURL, p.tags, u.firstName AS uploader
        FROM photogallerydb.Photo p
        JOIN users u ON p.userID = u.userID
        WHERE p.albumID=%s;
    '''
    cursor.execute(statement, (albumID,))
    results = cursor.fetchall()
    connection.close() 
    
    items = []
    for item in results:
        photo = {}
        photo['photoID'] = item['photoID']
        photo['albumID'] = item['albumID']
        photo['title'] = item['title']
        photo['description'] = item['description']
        photo['photoURL'] = item['photoURL']
        photo['tags'] = item['tags']
        photo['uploader'] = item['uploader']  # Include uploader's name
        items.append(photo)

    # Pass creator to template
    return render_template('viewphotos.html', 
                           photos=items, 
                           albumID=albumID, 
                           albumName=albumMeta['name'],
                           creator=albumMeta['creator'])  # Pass creator



@app.route('/album/<string:albumID>/addPhoto', methods=['GET', 'POST'])
def add_photo(albumID):
    """ Create new photo under album route. """
    token = request.cookies.get('jwtlogin_SQL')
    if not token:
        return redirect(url_for('login', message="You need to log in to perform this action."))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded["userID"]
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.PyJWTError:
        return redirect(url_for('login'))

    if request.method == 'POST':    
        file = request.files['imagefile']
        title = request.form['title']
        description = request.form['description']
        tags = request.form['tags']

        if file and allowed_file(file.filename):
            photoID = uuid.uuid4()
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)            
            
            uploadedFileURL = s3uploading(filename, filenameWithPath)
            ExifData = getExifData(filenameWithPath)

            connection = get_database_connection()
            cursor = connection.cursor()
            ExifDataStr = json.dumps(ExifData)

            # Insert with userID
            statement = '''INSERT INTO photogallerydb.Photo 
                           (photoID, albumID, userID, title, description, tags, photoURL, EXIF) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s);'''

            result = cursor.execute(statement, (photoID, albumID, user_id, title, description, tags, uploadedFileURL, ExifDataStr,))
            connection.commit()
            connection.close()

        return redirect(f'''/album/{albumID}''')

    else:
        connection = get_database_connection()
        cursor = connection.cursor()
        statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID=%s;'''
        cursor.execute(statement, (albumID,))
        albumMeta = cursor.fetchall()
        connection.close()

        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])




@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET'])
def view_photo(albumID, photoID):  
    """ Photo page route. """
    connection = get_database_connection()
    cursor = connection.cursor()

    # Get album info
    statement = '''SELECT * FROM photogallerydb.Album WHERE albumID=%s;'''
    cursor.execute(statement, (albumID,))
    albumMeta = cursor.fetchall()

    # Get photo + uploader info (JOIN with users table)
    statement = '''
        SELECT p.*, u.firstName AS uploader
        FROM photogallerydb.Photo p
        JOIN users u ON p.userID = u.userID
        WHERE p.albumID=%s AND p.photoID=%s;
    '''
    cursor.execute(statement, (albumID, photoID))
    results = cursor.fetchall()
    connection.close()

    if len(results) > 0:
        photo = {}
        photo['photoID'] = results[0]['photoID']
        photo['title'] = results[0]['title']
        photo['description'] = results[0]['description']
        photo['tags'] = results[0]['tags']
        photo['photoURL'] = results[0]['photoURL']
        photo['EXIF'] = json.loads(results[0]['EXIF'])
        photo['uploader'] = results[0]['uploader']  # Include uploader's name

        # Format dates
        createdAt = datetime.strptime(str(results[0]['createdAt']), "%Y-%m-%d %H:%M:%S")
        updatedAt = datetime.strptime(str(results[0]['updatedAt']), "%Y-%m-%d %H:%M:%S")

        createdAt_UTC = timezone("UTC").localize(createdAt)
        updatedAt_UTC = timezone("UTC").localize(updatedAt)

        photo['createdAt'] = createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")
        photo['updatedAt'] = updatedAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")

        tags = photo['tags'].split(',')
        exifdata = photo['EXIF']
        
        return render_template('photodetail.html', photo=photo, tags=tags, exifdata=exifdata, albumID=albumID, albumName=albumMeta[0]['name'])
    else:
        return render_template('photodetail.html', photo={}, tags=[], exifdata={}, albumID=albumID, albumName="")




@app.route('/album/search', methods=['GET'])
def search_album_page():
    """ search album page route.

    get:
        description: Endpoint to return all the matching albums.
        responses: Returns all the albums based on a particular query.
    """ 
    query = request.args.get('query', None)
    original_query = query
    query = '%' + query + '%'

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Album WHERE name LIKE %s UNION SELECT * FROM photogallerydb.Album WHERE description LIKE %s;'''
    cursor.execute(statement, (query, query))

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
        album={}
        album['albumID'] = item['albumID']
        album['name'] = item['name']
        album['description'] = item['description']
        album['thumbnailURL'] = item['thumbnailURL']
        items.append(album)

    return render_template('searchAlbum.html', albums=items, searchquery=original_query)



@app.route('/album/<string:albumID>/search', methods=['GET'])
def search_photo_page(albumID):
    """ search photo page route.

    get:
        description: Endpoint to return all the matching photos.
        responses: Returns all the photos from an album based on a particular query.
    """ 
    query = request.args.get('query', None)
    original_query = query
    query = '%'+query+'%'

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Photo WHERE title LIKE %s AND albumID=%s 
                    UNION SELECT * FROM photogallerydb.Photo WHERE description LIKE %s AND albumID=%s 
                    UNION SELECT * FROM photogallerydb.Photo WHERE tags LIKE %s AND albumID=%s
                    UNION SELECT * FROM photogallerydb.Photo WHERE EXIF LIKE %s AND albumID=%s;'''
    cursor.execute(statement, (query, albumID, query, albumID, query, albumID, query, albumID, ))

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
        photo={}
        photo['photoID'] = item['photoID']
        photo['albumID'] = item['albumID']
        photo['title'] = item['title']
        photo['description'] = item['description']
        photo['photoURL'] = item['photoURL']
        items.append(photo)

    return render_template('searchPhoto.html', photos=items, searchquery=original_query, albumID=albumID)



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
