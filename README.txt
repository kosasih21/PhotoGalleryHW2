Vincentius Kosasih

Here are the two websites.
http://54.82.239.95:5001/
http://54.82.239.95:5000/

The two credentials you can user are described below. They work on both websites equally.
vkosasih3@gatech.edu
-

vkosasih3+2@gatech.edu
-

SQL Version
I started development by initially trying to create the user table in my SQL. I tried using several methods including the SQL workbench and the inline MySQL console. But I concluded that I had to install my SQL on the EC2 in line console and then manually add the table using MySQL commands after checking documentation.

I created a set of HTML files to support the login sign up and confirm pages. And tested the links directly by creating a link in the NAV bar without any conditions. I won’t show the html files here but they are very straight forward.

I then created the signup flask route. This proved to be the most difficult as it was my first route. I have experience with flask but no experience with bcrypt or itsdangerous or SES. After playing around I decided to save the hashed password in the database using this command below.

password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

token = serializer.dumps(email, salt="email-confirmation")
confirm_url = f"54.82.239.95:5000/confirm/{token}"
email_body = f"Click here to verify your email: {confirm_url}"
send_email(email, email_body)

The code above demonstrates how I created the token using the itsdangerous serializer. There was a lot of fluff in the documentation but again, after some youtube videos, I was able to figure it out. It turned out to be much simpler than I anticipated.

I went ahead and configured SES as it describes in the homework 2 PDF. And made sure to verify my Georgia Tech e-mail address as well as the given e-mail address in the submission instructions. I had to modify the send e-mail function to properly work with my configuration as shown in the code below.

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

The confirm token route verifies the user using the database connection shown above. It changes an attribute in the user data to verify their account and then closes the connection.


if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
        response = make_response(redirect(url_for('home_page')))
        token = jwt.encode({"userID": user_id, "exp": datetime.utcnow() + timedelta(days=1)}, SECRET_KEY, algorithm="HS256")
        response.set_cookie("jwtlogin_SQL", token, httponly=True, samesite='Strict')
        return response
    else:
        return render_template("login.html", message="Incorrect password")

The above bcrypt.checkpw is how I was able to check my password when logging into the app. As long as the encoding and the other settings line up like the algorithm then the password will allow you to log in. The response is then set to save the cookie for the JWT login.

I then changed the NAV bar so that it conditionally displays certain things when a user is logged in versus when a user is logged out. When a user is logged in I made it so that it pulls the username and welcomes that user in the NAV bar as well as gives an option for a logout. The log out presents the user with a confirmation dialog where they can say yes or no to logging out. The logged in user can create albums properly and the logged out user is prompted to create an account or login in the NAV bar. The logout function just clears the JWT token and refreshes the page so that the user is no longer saved in the HTTP token.
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('home_page')))
    response.set_cookie("jwtlogin_SQL", "", expires=0)
    return response

After getting the login and user management features locked and dialed in I modified the create album and add photo method routes to properly save and store the user that created the album or photo. I just added an attribute or trait to the saved database entry and stored it in the metadata where the front end can access it and also display in all relevant pages.

I created a set of delete routes starting with a photo that goes to S3 and takes the URL parses it and then deletes it from the S3 buckets and then the SQL database. I used this as a starting point to delete photo album as well and just looped through the images to delete from S3 and then deleted all of the album’s metadata from the database including all photos inside the album.

       try:
            # Delete the file from S3
            s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                              aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
            s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=s3_key)
            print(f"Deleted photo from S3: {s3_key}")
        except Exception as e:
            print(f"Error deleting from S3: {e}")

S3 excerpt to show how files are deleted from S3.

statement = '''
            DELETE FROM photogallerydb.Photo
            WHERE photoID = %s AND albumID = %s;
        '''
        cursor.execute(statement, (photoID, albumID))
        connection.commit()

The excerpt above shows how I deleted photos from the SQL database. It follows a similar suit for the rest of the deletes that requires the metadata to be deleted.

The delete account route was a little bit more tricky but for the most part straightforward. It searches for all of the user’s created albums and photos and deletes from S3 and MySQL respectively. It uses a lot of code from delete album and delete photo. It also clears the token much similarly to the logout feature.



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
 



NoSQL Version
The no SQL version was much more manageable after completing the sequel version. I started by creating the Dynamo DB table using the AWS console online. It took me a little bit to navigate the console properly but I was able to create the table properly and added e-mail as a secondary index to be able to parse quickly.

I basically pasted over all of the login, sign up, and confirm features in terms of HTML, but modified the routes so that they properly reference the dynamodb database for users. I had a really big issue with my tables but it was easily solved when I realized that my code was referencing the same table for photos and albums as it was for users. The two versions are pretty much identical in the way that it uses Bcrypt and JWT to store login States and hash passwords. 

I also added the same logout feature that clears the tokens. And then proceeded to modify the front end HTML to also conditionally display login, log out, and create functions in the NAV bar based on if a user is logged in or not.

I then also modified the create album and add photo roots to include the user ID to be able to keep track of the author of the album or photo. This one was a little bit more difficult on the Dynamo DB side because I have a lot of experience with my SQL but much less experience with dynamodb. This applies to most of the user creation and management side but I watched a few YouTube videos on how people used dynamodb to store login information and I was able to figure it out.

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

Here I just added the uploaderID. Similarly in the album.

The delete routes album photo and accounts were pretty straightforward after I copied it from the SQL version for the S3 side and then a little bit of troubleshooting solved the deletion of entries in Dynamo DB. The delete account also follows a similar logic as the SQL version. And the noSQL version also utilizes the same token technology I previously explained in the SQL version in logoout and delete account.

table.delete_item(
            Key={
                'albumID': photo['albumID'],
                'photoID': photo['photoID']
            }
        )
Excerpt to show how I deleted items from the table.

# delete user
    userTable.delete_item(
        Key={'userId': user_id}
    )
print(f"Deleted user {user_id}")

Excerpt that shows how to delete user from the table.

I realized I had to secure my routes that only logged in users should only be allowed to access. I coded a helper function: get_logged_in_user() to retrieve the user logged in’s token and redirected the user for exclusive methods in case they were not authorized.

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


The biggest problem I encountered in developing the Dynamo DB version of the app was with the tokens. For some reason when I returned to the SQL version my app broke due to some JWT issues in the app. I dug around for a few hours and found out that JWT actually stores their tokens across the same server, so the app being on the same IP and different ports caused some major issues. This was easily fixable by creating different named JWT tokens.











Where to find features
The grader can find all relevant login information at the top of the page. The grader can login to access the full feature suite of my app. All relevant user management features are displayed in the navbar and follow a simple workflow.

The grader can delete exact photos by clicking the delete button at the bottom of viewing an exact photo. Album deletion is in the main album view page. Accounts can be deleted using the big button a the top of the screen when logged in. Shown in the screenshots below.
https://imgur.com/a/Z4dnNWi

