import express from 'express';
import { createServer } from 'http';
import path from 'path';
import cors from 'cors';
import connectDatabase from './config/database';
import * as AppModule from './app/modules/index';
import indexRoute from './routes/index';

// Set host and port from environment variables or default values
const host = process.env.HOST ?? 'localhost';
const port = process.env.PORT ? Number(process.env.PORT) : 3000;

// Create an instance of Express and an HTTP server
const app = express();
const server = createServer(app);

// Destructure modules from AppModule
const { AuthModule, UserModule } = AppModule;
const { UserRoute } = UserModule;
const { AuthController, AuthRoute } = AuthModule;

// Initialize AuthController
const authController = new AuthController();

// Connect to the database
connectDatabase();

// CORS configuration options
const corsOptions: cors.CorsOptions = {
  origin: true,
  methods: 'GET,HEAD,PUT,POST,DELETE',
  credentials: true,
  exposedHeaders: ['x-auth-token'],
};

// Apply middleware to Express app
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Define routes
app.use('/', indexRoute);
app.use('/api/auth', AuthRoute);

/**
 * Middleware function to authenticate API requests.
 * This function is used to check if a user is authenticated before allowing access to certain routes.
 *
 * @param {import('express').Request} req - The request object.
 * @param {import('express').Response} res - The response object.
 * @param {import('express').NextFunction} next - The next middleware function in the stack.
 *
 * @returns {void}
 */
app.all('/api/v1/*', (req, res, next) => authController.isAuthenticate(req, res, next));

// User-related routes
app.use('/api/v1/user', UserRoute);

/**
 * Handles the root ("/") route of the application.
 *
 * @param {import('express').Request} req - The request object.
 * @param {import('express').Response} res - The response object.
 *
 * @returns {void}
 */
app.get('/', (req, res) => {
  res.send({ message: 'Hello API' });
});

/**
 * Listens for incoming connections on the specified host and port.
 *
 * @param port - The port number to listen on.
 * @param host - The host name or IP address to listen on.
 * @param callback - A function to be called when the server starts listening.
 *
 * @returns {void}
 */
server.listen(port, host, () => {
  console.log(`[ ready ] http://${host}:${port}`);
});
