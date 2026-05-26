require('dotenv').config()

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
})

//middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ message: "Access denied, no token provided" })
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Invalid or expired token "})
        }
        req.user = user
        next()
    })
}


// get all users
app.get('/users',authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM users')
        res.json(result.rows)
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
})


// get single user by id
app.get('/users/:id',authenticateToken, async (req, res) => {
    try {
        const { id } = req.params
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id])

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" })
        }

        res.json(result.rows[0])
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
})

//register
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body

        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required."})
        }

        const handlePassword = await bcrypt.hash(password, 10)
        const result = await pool.query(
            'INSERT INTO auth (username, password) VALUES ($1, $2) RETURNING*',
            [username, handlePassword]
        )

        res.status(201).json({ message: "User registered successfully" })
    } catch (error) {
        res.status(500).json({message: error.message})
    }
})

//login
app.post('/login', async (req, res) => {
    try{
        const { username, password} = req.body

        const result = await pool.query(
            'SELECT * FROM auth WHERE username = $1',
            [username]
        )

        if(result.rows.length === 0) {
            return res.status(401).json({ message: "Invalid credentials"})
        }

        const user = result.rows[0]
        const validPassword = await bcrypt.compare(password, user.password)

        if (!validPassword) {
            return res.status(401).json({ message: "Invalid credentials" })
        }
        
        const token = jwt.sign(
            { userId: user.id},
            process.env.JWT_SECRET,
            { expiresIn: '1h'}
        )

        res.json({ token })
    } catch(error) {
        res.status(500).json({message: error.message})
    }
})

app.post('/users',authenticateToken, async (req, res) => {
    try {
        const {name, age} = req.body

        if (!name || name.trim() === "") {
            return res.status(400).json({ message: "Name is required" })
        }

        if (!age || typeof age !== "number") {
            return res.status(400).json({message: "Age must be a number" })
        }
        
        const result = await pool.query(
            'INSERT INTO users (name, age) VALUES ($1, $2) RETURNING*',
            [name, age]
        )

        res.status(201).json(result.rows[0])
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
})

app.put('/users/:id',authenticateToken, async (req, res) => {
    try {
        const { id } = req.params
        const {name, age} = req.body

        const result = await pool.query (
            'UPDATE users SET name = $1, age = $2 WHERE id = $3 RETURNING*',
            [name, age, id]
        )

        if (result.rows.length === 0) {
            return res.status(404).json({ messsage: "User not found"})
        }

        res.json(result.rows[0])
    } catch(error) {
        res.status(500).json({message: error.message})
    }
})

app.delete('/users/:id',authenticateToken, async (req, res) => {
    try {
        const { id } = req.params
        const result = await pool.query (
            'DELETE FROM users WHERE id = $1 RETURNING * ',
            [id]
        )

        if (result.rows.length ===0) {
            return res.status(404).json({ message: "User not found"})
        }

        res.json({message: "User deleted successfully"})
    } catch(error) {
        res.status(500).json({message: error.message})
    }
})

app.listen(3000, () => {
    console.log("Server is running on port 3000")
})