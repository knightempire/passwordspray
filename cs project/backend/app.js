// Node.js backend using Express with PostgreSQL (server.js)
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const cors=require('cors');
const bcrypt = require('bcrypt');


const app = express();
const PORT = 3000;

const pool = new Pool({
    user: 'host',
    host: 'localhost',
    database: 'passwordspary',
    password: '',
    port: 3306,
});
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

//route register
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    // Validate input
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        // Check if the username or email already exists in the database
        const existingUser = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (existingUser.rows.length > 0) {
            if (existingUser.rows[0].username === username) {
                return res.status(400).json({ error: 'Username already taken' });
            }
            if (existingUser.rows[0].email === email) {
                return res.status(400).json({ error: 'Email already registered' });
            }
        }

        // Insert new user into the database
        const newUser = await pool.query('INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *', [username, email, password]);
        res.status(201).json(newUser.rows[0]); // Send back the newly created user
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

//route login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = $1';
    console.log("api login requested");

    try {
        const result = await pool.query(query, [username]);
        console.log("User query executed:", result.rows);

        if (result.rows.length === 1) {
            const user = result.rows[0];
            console.log("User found:", user);

            // Check if the provided password matches the user's password
            if (user.password === password) {
                console.log("Password matched for user:", user.username);

                // User credentials are valid, now check if the username is in user_profile table
                const profileQuery = 'SELECT * FROM user_profile WHERE username = $1';
                const profileResult = await pool.query(profileQuery, [username]);
                console.log("Profile query executed:", profileResult.rows);

                if (profileResult.rows.length === 1) {
                    // Username is present in user_profile table
                    console.log("User profile found for:", user.username);
                    res.status(200).json({ message: 'Login successful', user: user, responseNumber: 1 });
                } else {
                    // Username is not present in user_profile table
                    console.log("No user profile found for:", user.username);
                    res.status(200).json({ message: 'Login successful', user: user, responseNumber: 2 });
                }
            } else {
                console.log("Invalid password for user:", user.username);
                res.status(401).send('Invalid password');
            }
        } else {
            console.log("User not found with username:", username);
            res.status(401).send('Invalid username');
        }

    } catch (error) {
        console.error("Error occurred:", error);
        res.status(500).send('Error logging in');
    }
});




//route insert profile
app.post('/api/profile', async (req, res) => {
    const { username, full_name, birth_date, bio } = req.body;

    try {
        // Insert new user profile into the user_profile table
        const newUserProfile = await pool.query(
            'INSERT INTO user_profile (username, full_name, birth_date, bio) VALUES ($1, $2, $3, $4) RETURNING *',
            [username, full_name, birth_date, bio]
        );

        res.status(201).json(newUserProfile.rows[0]); // Send back the newly created user profile
    } catch (error) {
        console.error('Error creating user profile:', error);
        res.status(500).json({ error: 'Failed to create user profile' });
    }
});



// Route to check user
app.post('/api/checkuser', async (req, res) => {
    const { username } = req.body;

    try {
        // Query the users table to check if the username exists
        const userQuery = await pool.query('SELECT * FROM user_profile WHERE username = $1', [username]);

        // If the username exists, return the user profile
        if (userQuery.rows.length > 0) {
            res.status(200).json({ exists: true, userProfile: userQuery.rows[0] });
        } else {
            res.status(200).json({ exists: false, message: 'User not found' });
        }
    } catch (error) {
        console.error('Error checking user:', error);
        res.status(500).json({ error: 'Failed to check user' });
    }
});


//route view profile
app.post('/api/viewprofile', async (req, res) => {
    const { username } = req.body;

    try {
        // Insert new user profile into the user_profile table
        const newUserProfile = await pool.query(
            'SELECT * FROM user_profile WHERE username = $1',
            [username]
        );

        res.status(201).json(newUserProfile.rows[0]); // Send back the newly created user profile
    } catch (error) {
        console.error('Error creating user profile:', error);
        res.status(500).json({ error: 'Failed to create user profile' });
    }
});



//route update profile
app.post('/api/updateprofile', async (req, res) => {
    const { username, full_name, birth_date, bio } = req.body;

    try {
        // Update the user profile in the user_profile table
        const updatedProfile = await pool.query(
            'UPDATE user_profile SET full_name = $1, birth_date = $2, bio = $3 WHERE username = $4 RETURNING *',
            [full_name, birth_date, bio, username]
        );

        res.status(200).json(updatedProfile.rows[0]); // Send back the updated user profile
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).json({ error: 'Failed to update user profile' });
    }
});


app.post('/api/bookmark', async (req, res) => {
    const { username, category, url } = req.body;

    try {
        // Check if the bookmark already exists
        const existingBookmark = await pool.query('SELECT * FROM bookmark WHERE username = $1 AND category = $2 AND url = $3', [username, category, url]);

        if (existingBookmark.rows.length > 0) {
            // If bookmark already exists, delete the existing bookmark
            await pool.query('DELETE FROM bookmark WHERE username = $1 AND category = $2 AND url = $3', [username, category, url]);

            // Return success response
            return res.status(201).json({ message: 'Existing bookmark deleted' });
        } else {
            // Insert the new bookmark into the database
            await pool.query('INSERT INTO bookmark (username, category, url) VALUES ($1, $2, $3)', [username, category, url]);

            // Return success response
            return res.status(200).json({ message: 'New bookmark added successfully' });
        }
    } catch (error) {
        // Handle any errors that occur during the process
        console.error('Error adding/updating bookmark:', error);
        return res.status(500).json({ error: 'Failed to add/update bookmark' });
    }
});



app.post('/api/viewbookmark', async (req, res) => {
    const { username, category } = req.body;

    try {
        // Query the bookmark table to retrieve data based on username and category
        const bookmarkData = await pool.query('SELECT * FROM bookmark WHERE username = $1 AND category = $2', [username, category]);

        // Check if any bookmark data is found
        if (bookmarkData.rows.length > 0) {
            // If data found, return it in the response
            return res.status(200).json(bookmarkData.rows);
        } else {
            // If no data found, return a message indicating it
            return res.status(404).json({ message: 'No bookmarks found for the provided username and category' });
        }
    } catch (error) {
        // Handle any errors that occur during the process
        console.error('Error fetching bookmark data:', error);
        return res.status(500).json({ error: 'Failed to fetch bookmark data' });
    }
});







// API endpoint for forget password functionality
app.post('/api/forget', (req, res) => {
    const { username, email } = req.body;
    
    // Check if the provided username and email match any records in the users table
    const user = users.find(u => u.username === username && u.email === email);
    
    if (user) {
        // If a matching user is found, redirect to changepassword.html
        res.redirect('./changepassword.html');
    } else {
        // If no matching user is found, return an error response
        res.status(404).json({ error: 'User not found' });
    }
});


// API endpoint for changing password
app.post('/api/changepassword', (req, res) => {
    const { username, password } = req.body;

    // Find the user in the users array
    const userIndex = users.findIndex(user => user.username === username);

    if (userIndex !== -1) {
        // Update the user's password
        users[userIndex].password = password;
        res.status(200).json({ message: 'Password updated successfully' });
    } else {
        // If user not found, return an error response
        res.status(404).json({ error: 'User not found' });
    }
});

















app.post('/api/registeruser', async (req, res) => {
    const { gmail, password } = req.body;
  
    try {
      // Check if password is provided
      if (!password) {
        throw new Error('Password is required');
      }
  
      // Hash the password using bcrypt
      const hashedPassword = await bcrypt.hash(password, 10); // Using 10 salt rounds
  
      // Insert user details into the database
      const queryText = 'INSERT INTO dummy (gmail, password) VALUES ($1, $2)';
      const queryValues = [gmail, hashedPassword];
  
      await pool.query(queryText, queryValues, (err, result) => {
        if (err) {
          console.error('Error registering user: ' + err);
          res.status(500).json({ error: 'Error registering user' });
        } else {
          console.log('User registered successfully');
          res.status(200).json({ message: 'User registered successfully' });
        }
      });
    } catch (error) {
      console.error('Error hashing password: ' + error);
      res.status(500).json({ error: 'Error hashing password' });
    }
});

// Endpoint to login a user
app.post('/api/loginuser', async (req, res) => {
    const { gmail, password } = req.body;

    try {
        // Check if username and password are provided
        if (!gmail || !password) {
            throw new Error('Gmail address and password are required');
        }

        // Query the database to find the user by their gmail address
        const queryText = 'SELECT * FROM dummy WHERE gmail = $1';
        const { rows } = await pool.query(queryText, [gmail]);

        // If no user found with the provided gmail address
        if (rows.length === 0) {
            throw new Error('User not found');
        }

        const user = rows[0];

        // Compare the provided password with the hashed password stored in the database
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            throw new Error('Incorrect password');
        }

        console.log('User logged in successfully');
        res.status(200).json({ message: 'User logged in successfully' });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(401).json({ error: error.message });
    }
});





app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});