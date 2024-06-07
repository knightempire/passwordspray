const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const passport = require('passport');
const dotenv = require('dotenv');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const port = 3000 || null;

dotenv.config();

app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const {
    DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_DATABASE,
    DB_WAIT_FOR_CONNECTIONS,
    DB_CONNECTION_LIMIT,
    DB_QUEUE_LIMIT,
    SESSION_SECRET,
    JWT_SECRET,
    JWT_EXPIRY,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET
} = process.env;

const dbConfig = {
    host: DB_HOST,
    port: 3306,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE,
    waitForConnections: DB_WAIT_FOR_CONNECTIONS === 'true', // Convert string to boolean
    connectionLimit: parseInt(DB_CONNECTION_LIMIT, 10),
    queueLimit: parseInt(DB_QUEUE_LIMIT, 10),
};

const pool = mysql.createPool(dbConfig);


(async () => {
    try {
        // Attempt to get a connection from the pool
        const connection = await pool.getConnection();
        
        // If connection successful, log a success message
        console.log('Database connected successfully');
        
        // Release the connection back to the pool
        connection.release();
    } catch (error) {
        // Log an error message if connection fails
        console.error('Error connecting to the database:', error);
        process.exit(1); // Terminate the application process
    }
})();


app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
    // You can handle the user's profile here (e.g., save to database)
    return done(null, profile);
}));

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

app.get('/auth/google',
    passport.authenticate('google', { 
        scope: ['profile', 'email', 'openid', 'https://www.googleapis.com/auth/user.birthday.read', 'https://www.googleapis.com/auth/user.phonenumbers.read'] 
    }));

    
    app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    async (req, res) => {
        // Log the entire req.user object
        console.log('User Profile:', req.user);
        
        try {
            // Extract user's email from the Google OAuth response
             const email = req.user.emails[0].value;
             const givenName = req.user.name.givenName; // Access given name
             const dob = req.user.birthday; // Access date of birth
             const phone = req.user.phone; // Access phone number
 
             console.log('User Gmail:', email);
             console.log('User Given Name:', givenName);
 

            // Check if the user already exists in the database
            const [existingUser] = await pool.query('SELECT * FROM users WHERE gmail = ?', [email]);
            
            if (!existingUser.length) {
                // If the user doesn't exist, insert their profile into the database
                await pool.query('INSERT INTO users (gmail, password) VALUES (?, ?)', [email, email]);
            }

            // User exists or has been registered, proceed with login (authenticate against password)
            // You need to implement password-based authentication here
            // Once authenticated, generate session token or JWT and proceed with authentication

            // Redirect the user to the home page or dashboard
            res.redirect('');
        } catch (error) {
            console.error('Error during OAuth callback:', error);
            res.status(500).send('Internal Server Error');
        }
    });



// app.get('/', (req, res) => {
//     res.send('Home Page');
// });


//function to create token


const createtoken = (req, res, rows) => {
    // Assuming rows contain user data with a username field
    const username = rows[0].username;

    // Sign the token with the username instead of email
    const token = jwt.sign({ username: username }, JWT_SECRET, {

        
        expiresIn: JWT_EXPIRY,
    });

    // Assuming you are using Express and want to store the token in the session
    req.session.jwtToken = token;

    // Return the token
    return token;
};




const authenticateToken = async (req, res, next) => {
    try {
        // Check if Authorization header exists
        if (!req.headers.authorization) {
            return res.status(401).json({ error: 'Unauthorized' }); // Return 401 Unauthorized status
        }

        // Retrieve token from request headers and split it
        const token = req.headers.authorization.split(' ')[1];
        console.log("Token:", token); // Print token value

        // Verify token
        jwt.verify(token, "learn@1234", async (err, decodedToken) => {
            if (err) {
                console.error('Authentication error:', err.message);
                // Token is invalid or expired, send 401 Unauthorized response to client
                return res.status(401).json({ error: 'Unauthorized' });
            } else {
                console.log('Decoded Token:', decodedToken); // Print decoded token data
                
                // Decode the token to get the username
                const username = decodedToken.username;
                console.log(username)

                // Retrieve user data from the database based on the username
                const userData = await getUserDataByUsername(username);

                if (!userData) {
                    // User not found in the database, send 401 Unauthorized response
                    console.error('User not found');
                    return res.status(401).json({ error: 'Unauthorized' });
                }

                // Set user information in request object
                req.user = userData;
                next(); // Proceed to next middleware
            }
        });
    } catch (err) {
        console.error('Error in authentication middleware:', err.message);
        res.status(500).send('Internal Server Error');
    }
};


//decoding the token
app.post('/api/decodeToken', async (req, res) => {
    console.log('api decode requested');
    try {
        // Extract the token from the request body
        const { token } = req.body;
    
        console.log(token)

        // Verify and decode the token
        const decodedToken = jwt.verify(token, JWT_SECRET);
        // console.log(decodedToken)

        // Extract username from decoded token
        const { username } = decodedToken;

        // Get a connection from the pool
        const connection = await pool.getConnection();

        try {
            // Query the database to retrieve user data based on username
            const [rows] = await connection.execute('SELECT user_id,name,phoneNumber,username FROM users WHERE username = ?', [username]);

            // Check if user exists in the database
            if (rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Get the user data from the query results
            const userData = rows[0];
            console.log('decoded token');

            // Send user data back to the client
            res.status(200).json(userData);
        } catch (error) {
            console.error('Error querying database:', error.message);
            res.status(500).json({ error: 'Internal server error' });
        } finally {
            // Release the connection back to the pool
            connection.release();
        }
    } catch (error) {
        // Handle any errors, such as token validation failure
        console.error('Error decoding token:', error.message);
        res.status(400).json({ error: 'Failed to decode token' });
    }
});



// Endpoint to login a user
// app.post('/api/loginuser', async (req, res) => {
//     const { gmail, password } = req.body;

//     try {
//         // Check if username and password are provided
//         if (!gmail || !password) {
//             throw new Error('Gmail address and password are required');
//         }

//         // Query the database to find the user by their gmail address
//         const [rows] = await pool.query('SELECT * FROM users WHERE gmail = ?', [gmail]);

//         // If no user found with the provided gmail address
//         if (rows.length === 0) {
//             throw new Error('User not found');
//         }

//         const user = rows[0];

//         // Compare the provided password with the hashed password stored in the database
        
//         const passwordMatch = await bcrypt.compare(password, user.password);

//         if (!passwordMatch) {
//             throw new Error('Incorrect password');
//         }

//         console.log('User logged in successfully');
//         res.status(200).json({ message: 'User logged in successfully' });
//     } catch (error) {
//         console.error('Error logging in user:', error);
//         res.status(401).json({ error: error.message });
//     }
// });





// Endpoint to login a user
app.post('/api/loginuser', async (req, res) => {
    const { gmail, password } = req.body;

    try {
        // Check if username and password are provided
        if (!gmail || !password) {
            throw new Error('Gmail address and password are required');
        }

        // Query the database to find the user by their gmail address
        const [rows] = await pool.query('SELECT * FROM users WHERE gmail = ?', [gmail]);

        // If no user found with the provided gmail address
        if (rows.length === 0) {
            throw new Error('User not found');
        }

        const user = rows[0];

        // Compare the provided password with the password stored in the database
        if (password !== user.password) {
            throw new Error('Incorrect password');
        }

        console.log('User logged in successfully');
        res.status(200).json({ message: 'User logged in successfully' });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(401).json({ error: error.message });
    }
});

  

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}).on('error', (err) => {
    console.error('Server start error:', err);
});



