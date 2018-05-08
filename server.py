from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

app = Flask(__name__)
app.secret_key = "thisisasecretkey"
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

mysql = connectToMySQL('flask_wall_db')

@app.route('/')
def index():
    #if a new page load, or recently cleared cookies
    #create session keys for later use to store inputted data
    #in the form, as well as store if there is a user logged in
    if not 'first_name' in session:
        session['first_name'] = ''
    if not 'last_name' in session:
        session['last_name'] = ''
    if not 'email' in session:
        session['email'] = ''
    if not 'user_logged_in_id' in session:
        session['user_logged_in_id'] = ''
    if not 'user_name' in session:
        session['user_name'] = ''
    return render_template('index.html')

@app.route('/checkreg', methods=['POST'])
def check_reg():
    info = request.form

    #store inputed information into session so that the user doesnt lose the data
    session['first_name'] = info['first_name']
    session['last_name'] = info['last_name']
    session['email'] = info['email']

    #starting the validation checks here
    if len(info['first_name']) < 1:
        flash('ef_fn')
    elif len(info['first_name']) <3 or not info['first_name'].isalpha():
        flash('a2_fn')

    if len(info['last_name']) < 1:
        flash('ef_ln')
    elif len(info['last_name']) < 3 or not info['last_name'].isalpha():
        flash('a2_ln')

    if len(info['email']) < 1:
        flash('ef_email')
    #checking if the email is a valid email format
    elif not EMAIL_REGEX.match(info['email']):
        flash('inv_email')
    #if it is a valid format then check if the email is in the database
    else:
        data = mysql.query_db("SELECT * FROM users")
        for e in data:
            if info['email'] == e['email']:
                flash('unav_email')

    if len(info['password']) < 1:
        flash('ef_pw')
    elif len(info['password']) < 8:
        flash('short_pw')
    
    if len(info['confirm_password']) < 1:
        flash('ef_cpw')
    if info['password'] != info['confirm_password']:
        flash('nm_pw')
    #done with validation checks

    #if there are any flash messages, that means we failed some validation, so 
    #redirect back to the index
    if '_flashes' in session:
        return redirect('/')  
    #else add the info to the database, and redirect to the success page
    else:
        pass_hash = bcrypt.generate_password_hash(info['password'])
        query = "INSERT INTO users (first_name, last_name, email, password_hash) \
                VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password_hash)s);"
        data = {
            'first_name' : info['first_name'],
            'last_name' : info['last_name'],
            'email' : info['email'],
            'password_hash' : pass_hash
        }
        mysql.query_db(query,data)
        session['user_name'] = info['first_name']
        session['user_logged_in_id'] = find_user_id(info['email'])
        flash("You've been successfully registered")
        return redirect('/message_board')

@app.route('/logincheck', methods=['POST'])
def logincheck():
    data = mysql.query_db("SELECT * FROM users")
    login_info = request.form
    found_user = False
    user_id = None
    #go through all emails in the database and see if there is a match
    for e in data:
        if login_info['email'] == e['email']:
            found_user = True
            user_id = e['id']
    #if the user is found check if the password is correct
    if found_user:
        query ="SELECT * FROM users WHERE id =%(id)s"
        ins_data = {'id':user_id}
        data_id = mysql.query_db(query,ins_data)
        if bcrypt.check_password_hash(data_id[0]['password_hash'], login_info['password']):
            session['user_logged_in_id'] = find_user_id(data_id[0]['email'])
            session['user_name'] = find_user_id(data_id[0]['name'])
            return redirect('/message_board')
        else:
            flash('bad_login')
            return redirect('/')
    flash('bad_login')
    return redirect('/')

@app.route('/message_board')
def success():
    if not session['user_logged_in_id']:
       flash('not_logged_in')
       return redirect('/')
    else:
        print(session)
        message_data = mysql.query_db("SELECT users.id, concat(users.first_name, ' ', users.last_name) as name, \
                             message, messages.created_at, messages.id as message_id \
                             FROM users \
                             JOIN messages ON users.id = messages.users_id \
                             ORDER BY messages.created_at DESC;")
        for e in message_data:
            print(e)
            this_message_id = e["message_id"]
            e["replies"] =[]
            comments = mysql.query_db("SELECT concat(users.first_name, ' ', users.last_name) as name, comment, \
                                        comments.created_at \
                                        FROM users \
                                        JOIN comments on users.id = comments.users_id \
                                        where messages_id = '" + str(this_message_id) + "';")
            for i in comments:
                print(i)
                e["replies"].append({
                    'name':i['name'], 
                    'comment':i['comment'],
                    'created_at':i['created_at']})
        print(message_data[0]['replies'])
        for data in message_data[0]['replies']:
            print(data['comment'])
        return render_template('message_board.html',data = message_data)

@app.route('/logout')
def logout():
    session.clear()
    flash('log_out')
    return redirect('/')

@app.route('/message_post',methods=['POST'])
def post_message():
    message = request.form['message']
    query = "INSERT INTO messages(users_id,message,created_at,updated_at) \
            values(%(user_id)s, %(message)s, now(), now());"
    data = {
        'user_id':session['user_logged_in_id'],
        'message':message
    }
    mysql.query_db(query,data)
    return redirect('/message_board')

@app.route('/comment_post',methods=['POST'])
def post_comment():
    print('entering post comment')
    messages_id = request.form['id']
    comment = request.form['comment']
    print(messages_id, comment, session['user_logged_in_id'])
    query = "INSERT INTO comments(messages_id, users_id, comment, created_at, updated_at) \
            VALUES(%(messages_id)s, %(users_id)s, %(comment)s, now(), now())"
    data = {
        "messages_id":messages_id,
        "users_id":session['user_logged_in_id'],
        "comment":comment
    }
    print("<-----------------------")
    mysql.query_db(query,data)
    return redirect('/message_board')

def find_user_id(email):
    query_name = "SELECT id FROM users WHERE email = %(email)s"
    query_email = {'email':email}
    db_id = mysql.query_db(query_name,query_email)
    return db_id[0]['id']

if __name__ == "__main__":
    app.run(debug=True)