import express from 'express';
import dotenv from 'dotenv';
import connectDB from './config/db.js';
import authRoutes from './routes/authRoutes.js'
import userRoutes from './routes/userRoutes.js'
import passport from 'passport';
import session from 'express-session';
import { client, httpRequestDurationMicroseconds } from './config/metrics.js';
import './config/passport.js';

dotenv.config();
connectDB();

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
// app.use(session({secret: 'secret', resave: false, saveUninitialized: true}));
// app.use(passport.initialize());
// app.use(passport.session());

app.use((req, res, next)=> {
    const end = httpRequestDurationMicroseconds.startTimer();
    res.on('finish', ()=>{
        end({method: req.method, route: req.route, code: res.statusCode});
    });
    next();
})

app.use('/metrics', async (req, res)=> {
    res.set('Content-Type', client.register.contentType);
    res.end(await client.register.metrics());
})

app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
