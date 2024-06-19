from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from calendar import monthrange, calendar

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Function to establish database connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Route for login page
@app.route('/')
def index():
    return render_template('login.html')

# Route for handling login form submission
@app.route('/login', methods=['POST'])
def login():
    userid = request.form['userid']
    password = request.form['password']
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE userid = ?', (userid,)).fetchone()
    conn.close()
    
    if user is None or not check_password_hash(user['password'], password):
        flash('Invalid username or password', 'error')
        return redirect(url_for('index'))
    
    # Store user information in session
    session['user'] = {
        'id': user['id'],
        'name': user['name'],
        'role': user['role']
    }
    
    # Redirect based on role
    if user['role'] == 'Admin':
        return redirect(url_for('admin'))
    elif user['role'] == 'Manager':
        return redirect(url_for('manager'))
    elif user['role'] == 'Employee':
        return redirect(url_for('employee'))
    else:
        flash('Unknown role', 'error')
        return redirect(url_for('index'))

# Route for admin dashboard - view records
@app.route('/admin')
def admin():
    if 'user' not in session or session['user']['role'] != 'Admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    records = conn.execute('SELECT id, name, role, userid FROM users').fetchall()
    conn.close()
    
    return render_template('admin.html', user=session['user'], records=records)


# Route for adding new record
@app.route('/admin/add_record', methods=['GET', 'POST'])

def add_record():
    if 'user' not in session or session['user']['role'] != 'Admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        
        id = request.form['id']
        name = request.form['name']
        role = request.form['role']
        userid = request.form['userid']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (id,name, role, userid, password) VALUES (?, ?, ?, ?, ?)', 
                         (id,name, role, userid, hashed_password))
            conn.commit()
            conn.close()
            flash('Record added successfully', 'success')
        except sqlite3.Error as e:
            print(f"Error inserting record: {e}")
            flash('Failed to add record', 'error')
        return redirect(url_for('admin'))
    
    return render_template('add_record.html', user=session.get('user'))



# Route for modifying record
@app.route('/admin/edit_record/<int:id>', methods=['GET', 'POST'])
def edit_record(id):
    if 'user' not in session or session['user']['role'] != 'Admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    record = conn.execute('SELECT id, name, role, userid FROM users WHERE id = ?', (id,)).fetchone()
    
    if request.method == 'POST':
        # Retrieve form data
        name = request.form['name']
        role = request.form['role']
        userid = request.form['userid']
        
        # Update record in database
        conn.execute('UPDATE users SET name = ?, role = ?, userid = ? WHERE id = ?', 
                     (name, role, userid, id))
        conn.commit()
        conn.close()
        
        flash('Record updated successfully', 'success')
        return redirect(url_for('admin'))
    
    conn.close()
    return render_template('edit_record.html', user=session['user'], record=record)

# Route for deleting record
@app.route('/admin/delete_record/<int:id>', methods=['POST'])
def delete_record(id):
    if 'user' not in session or session['user']['role'] != 'Admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash('Record deleted successfully', 'success')
    return redirect(url_for('admin'))


@app.route('/employee', methods=['GET', 'POST'])
def employee():
    if 'user' not in session or session['user']['role'] != 'Employee':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    user_id = session['user']['id']
    conn = get_db_connection()

    if request.method == 'POST':
        # Handle check-in or check-out
        if request.form['action'] == 'checkin':
            now = datetime.now()
            conn.execute('INSERT INTO attendance (user_id, checkin_time, status) VALUES (?, ?, ?)', (user_id, now, 'checked_in'))
            conn.commit()
            flash('Checked in successfully', 'success')

        elif request.form['action'] == 'checkout':
            now = datetime.now()
            attendance = conn.execute('SELECT * FROM attendance WHERE user_id = ? ORDER BY checkin_time DESC LIMIT 1', (user_id,)).fetchone()

            if attendance and attendance['status'] == 'checked_in':
                checkin_time = datetime.fromisoformat(attendance['checkin_time'])
                duration = now - checkin_time

                if duration >= timedelta(hours=8):
                    conn.execute('UPDATE attendance SET checkout_time = ?, status = ? WHERE id = ?', (now, 'checked_out', attendance['id']))
                    conn.commit()
                    flash('Checked out successfully', 'success')
                else:
                    flash('You must work at least 8 hours to check out', 'error')

    # Fetch today's attendance record if exists
    today = datetime.now().date()
    attendance = conn.execute('SELECT * FROM attendance WHERE user_id = ? AND DATE(checkin_time) = ?', (user_id, today)).fetchone()

    # Fetch leave requests
    leave_requests = conn.execute('SELECT * FROM leave_requests WHERE user_id = ?', (user_id,)).fetchall()

    conn.close()

    return render_template('employee.html', user=session['user'], attendance=attendance, leave_requests=leave_requests)

# Route for submitting leave request
@app.route('/employee/submit_leave', methods=['POST'])
def submit_leave():
    if 'user' not in session or session['user']['role'] != 'Employee':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    user_id = session['user']['id']
    leave_reason = request.form['leave_reason']
    leave_date = request.form['leave_date']

    conn = get_db_connection()
    conn.execute('INSERT INTO leave_requests (user_id, leave_date, leave_reason, status) VALUES (?, ?, ?, ?)', (user_id, leave_date, leave_reason, 'pending'))
    conn.commit()
    conn.close()

    flash('Leave request submitted successfully', 'success')
    return redirect(url_for('employee'))

@app.route('/manager')
def manager():
    if 'user' not in session or session['user']['role']!= 'Manager':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    leave_requests = conn.execute('SELECT * FROM leave_requests WHERE status =?', ('pending',)).fetchall()
    attendance_data = conn.execute('SELECT * FROM attendance').fetchall()
    conn.close()

    return render_template('manager.html', user=session['user'], leave_requests=leave_requests, attendance_data=attendance_data)

@app.route('/manager/accept_leave', methods=['POST'])
def accept_leave():
    if 'user' not in session or session['user']['role']!= 'Manager':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    request_id = request.form['request_id']
    conn = get_db_connection()
    conn.execute('UPDATE leave_requests SET status =? WHERE id =?', ('accepted', request_id))
    conn.commit()
    conn.close()

    flash('Leave request accepted successfully', 'uccess')
    return redirect(url_for('manager'))

@app.route('/manager')
@app.route('/manager/decline_leave', methods=['POST'])
def decline_leave():
    if 'user' not in session or session['user']['role']!= 'Manager':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    request_id = request.form['request_id']
    conn = get_db_connection()
    conn.execute('UPDATE leave_requests SET status =? WHERE id =?', ('declined', request_id))
    conn.commit()
    conn.close()

    flash('Leave request declined successfully', 'uccess')
    return redirect(url_for('manager'))






# Route for logging out
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user', None)
    flash('You have been logged out')
    return redirect('/')



# Main section to run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
