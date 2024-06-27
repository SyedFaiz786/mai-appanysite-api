// import bcrypt from 'bcryptjs';
// import jwt from 'jsonwebtoken';
// import response from '../../../helper/response';
// import UserModel from '../user/user.model';
// import AuthValidation from './auth.validation';
// import { sendEmail } from './emailService';
// import { Request, Response, NextFunction } from 'express';
// import path from 'path';import fs from 'fs';
// const configPath = path.resolve(__dirname, '../../../config/config.json');

// let config;

// try {
//     const rawData = fs.readFileSync(configPath, 'utf-8');
//     config = JSON.parse(rawData);
// } catch (error) {
//     console.error('Failed to load config file:', error);
//     throw error;
// }

// const authValidation = new AuthValidation();
// const secretKey: string = config.development.JWTsecret;
// const saltRounds: number = 10;

// interface TokenPayload {
//     id: string;
//     username: string;
//     email: string;
//     role: string;
// }

// export default class AuthController {
//     constructor() {}

//     async login(req: Request, res: Response, next: NextFunction): Promise<Response | void> {
//         try {
//             const { email, password } = req.body;

//             if (!email || !password) {
//                 return res.status(400).json(response.error(false, 'Email and password are required'));
//             }

//             const result = await authValidation.checkUser({ email });

//             if (result.success) {
//                 const matched = await bcrypt.compare(password, result.data.password);
//                 if (matched) {
//                     req.user = result.data;
//                     next();
//                 } else {
//                     return res.status(200).json(response.error(false, 'Incorrect email or password'));
//                 }
//             } else {
//                 return res.status(200).json(response.error(false, result.message));
//             }
//         } catch (e: any) {
//             return res.status(500).json(response.error(false, 'An error occurred', e.message));
//         }
//     }

//     async signup(req: Request, res: Response): Promise<Response> {
//         try {
//             const { username, email, password, phone } = req.body;

//             if (!username || !email || !password || !phone) {
//                 return res.status(400).json(response.error(false, 'Missing required fields'));
//             }

//             const hashedPassword = bcrypt.hashSync(password, saltRounds);

//             const newUser = await UserModel.create({
//                 username,
//                 email,
//                 password: hashedPassword,
//                 role: 'admin',
//             });

//             return res.status(201).json(response.single(true, 'New User Created', newUser));
//         } catch (e: any) {
//             console.error('Error in signup:', e);
//             return res.status(500).json(response.error(false, 'An error occurred during signup', e.message));
//         }
//     }

//     async forgotPassword(req: Request, res: Response): Promise<Response> {
//         try {
//             const { email } = req.body;
//             const user = await UserModel.findOne({ email });

//             if (!user) {
//                 return res.status(404).json(response.error(false, 'User not found'));
//             }

//             const token = jwt.sign({ id: user._id, username: user.username, email: user.email, role: user.role }, secretKey, { expiresIn: '1h' });
//             const resetLink = `http://${config.development.server.host}:${config.development.server.port}/api/auth/reset-password?token=${token}`;

//             const emailResponse = await sendEmail(user.email, 'Password Reset', `Click here to reset your password: ${resetLink}`);

//             if (emailResponse.success) {
//                 return res.status(200).json(response.single(true, 'Password reset email sent', null));
//             } else {
//                 return res.status(500).json(response.error(false, emailResponse.message, emailResponse.error));
//             }
//         } catch (e: any) {
//             return res.status(500).json(response.error(false, 'An error occurred', e.message));
//         }
//     }

//     async resetPassword(req: Request, res: Response): Promise<Response> {
//         try {
//             const { token, newPassword } = req.body;

//             const decoded = jwt.verify(token, secretKey) as TokenPayload;
//             const hashedPassword = bcrypt.hashSync(newPassword, saltRounds);

//             await UserModel.findByIdAndUpdate(decoded.id, { password: hashedPassword });

//             return res.status(200).json(response.single(true, 'Password reset successfully', null));
//         } catch (e: any) {
//             return res.status(500).json(response.error(false, 'An error occurred', e.message));
//         }
//     }

//     async prepareToken(req: Request, res: Response, next: NextFunction): Promise<void> {
//         try {
//             req.auth = {
//                 id: req.user!._id,
//                 username: req.user!.username,
//                 email: req.user!.email,
//                 role: req.user!.role,
//             };
//             next();
//         } catch (e: any) {
//             throw e;
//         }
//     }

//     generateToken(req: Request, res: Response, next: NextFunction): void {
//         req.tokenObject = {
//             token: jwt.sign(req.auth!, secretKey, {
//                 expiresIn: '30 days',
//             }),
//         };
//         next();
//     }

//     sendToken(req: Request, res: Response): void {
//         res.setHeader('x-auth-token', req.tokenObject!.token);
//         res.json(response.single(true, 'Enjoy your token!', { token: req.tokenObject!.token }));
//     }

//     async isAuthenticate(req: Request, res: Response, next: NextFunction): Promise<Response | void> {
//         try {
//             const token = req.headers['x-auth-token'] as string;
//             if (token) {
//                 const decoded = jwt.verify(token, secretKey) as TokenPayload;
//                 req.auth = decoded;
//                 const user = await UserModel.findOne({ _id: req.auth.id });
//                 return user ? next() : res.status(200).json(response.error(false, 'Failed to authenticate user'));
//             }
//             return res.json(response.error(false, 'You are not authenticated', 'No token provided'));
//         } catch (e: any) {
//             return res.json(response.error(false, e.name, e.message));
//         }
//     }

//     isUser(req: Request, res: Response, next: NextFunction): void {
//         if (req.auth!.role === 'user' || req.auth!.role === 'admin') {
//             next();
//         } else {
//             res.status(200).json(response.error(false, 'You are not admin or user', null));
//         }
//     }

//     isAdmin(req: Request, res: Response, next: NextFunction): void {
//         if (req.auth!.role === 'admin') {
//             next();
//         } else {
//             res.status(200).json(response.error(false, 'You are not admin', null));
//         }
//     }
// }


import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import response from '../../../helper/response';
import UserModel from '../user/user.model';
import AuthValidation from './auth.validation';
import { sendEmail } from './emailService';
import { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';

const configPath = path.resolve(__dirname, '../../../config/config.json');

let config;

try {
    const rawData = fs.readFileSync(configPath, 'utf-8');
    config = JSON.parse(rawData);
} catch (error) {
    console.error('Failed to load config file:', error);
    throw error;
}

const authValidation = new AuthValidation();
const secretKey: string = config.development.JWTsecret;
const saltRounds: number = 10;

interface TokenPayload {
    id: string;
    username: string;
    email: string;
    role: string;
}

export default class AuthController {
    constructor() {}

    async login(req: Request, res: Response, next: NextFunction): Promise<Response | void> {
        try {
            const { email, password } = req.body;

            if (!email || !password) {
                return res.status(400).json(response.error(false, 'Email and password are required'));
            }

            const result = await authValidation.checkUser({ email });

            if (result.success) {
                const matched = await bcrypt.compare(password, result.data.password);
                if (matched) {
                    req.user = result.data;
                    next();
                } else {
                    return res.status(200).json(response.error(false, 'Incorrect email or password'));
                }
            } else {
                return res.status(200).json(response.error(false, result.message));
            }
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }

    async signup(req: Request, res: Response): Promise<Response> {
        try {
            const { username, email, password, phone } = req.body;

            if (!username || !email || !password || !phone) {
                return res.status(400).json(response.error(false, 'Missing required fields'));
            }

            const hashedPassword = bcrypt.hashSync(password, saltRounds);

            const newUser = await UserModel.create({
                username,
                email,
                password: hashedPassword,
                role: 'admin',
            });

            return res.status(201).json(response.single(true, 'New User Created', newUser));
        } catch (e: any) {
            console.error('Error in signup:', e);
            return res.status(500).json(response.error(false, 'An error occurred during signup', e.message));
        }
    }

    async logout(req: Request, res: Response): Promise<Response> {
        try {
            // Optionally perform any additional logout logic here
            // For example, clear any tokens or session information
            // Example: Clear token from headers
            res.removeHeader('x-auth-token'); // Assuming token is stored in headers

            // You can also clear tokens stored in cookies or local storage on the client side

            return res.status(200).json(response.single(true, 'Logout successful', null));
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }

    async forgotPassword(req: Request, res: Response): Promise<Response> {
        try {
            const { email } = req.body;
            const user = await UserModel.findOne({ email });

            if (!user) {
                return res.status(404).json(response.error(false, 'User not found'));
            }

            const token = jwt.sign({ id: user._id, username: user.username, email: user.email, role: user.role }, secretKey, { expiresIn: '1h' });
            const resetLink = `http://${config.development.server.host}:${config.development.server.port}/api/auth/reset-password?token=${token}`;

            const emailResponse = await sendEmail(user.email, 'Password Reset', `Click here to reset your password: ${resetLink}`);

            if (emailResponse.success) {
                return res.status(200).json(response.single(true, 'Password reset email sent', null));
            } else {
                return res.status(500).json(response.error(false, emailResponse.message, emailResponse.error));
            }
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }

    async resetPassword(req: Request, res: Response): Promise<Response> {
        try {
            const { token, password } = req.body;

            const decoded = jwt.verify(token, secretKey) as TokenPayload;
            const hashedPassword = bcrypt.hashSync(password, saltRounds);

            await UserModel.findByIdAndUpdate(decoded.id, { password: hashedPassword });

            return res.status(200).json(response.single(true, 'Password reset successfully', null));
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }

    async prepareToken(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            req.auth = {
                id: req.user!._id,
                username: req.user!.username,
                email: req.user!.email,
                role: req.user!.role,
            };
            next();
        } catch (e: any) {
            throw e;
        }
    }

    generateToken(req: Request, res: Response, next: NextFunction): void {
        req.tokenObject = {
            token: jwt.sign(req.auth!, secretKey, {
                expiresIn: '30 days',
            }),
        };
        next();
    }

    sendToken(req: Request, res: Response): void {
        res.setHeader('x-auth-token', req.tokenObject!.token);
        res.json(response.single(true, 'Enjoy your token!', { token: req.tokenObject!.token }));
    }

    async isAuthenticate(req: Request, res: Response, next: NextFunction): Promise<Response | void> {
        try {
            const token = req.headers['x-auth-token'] as string;
            if (token) {
                const decoded = jwt.verify(token, secretKey) as TokenPayload;
                req.auth = decoded;
                const user = await UserModel.findOne({ _id: req.auth.id });
                return user ? next() : res.status(200).json(response.error(false, 'Failed to authenticate user'));
            }
            return res.json(response.error(false, 'You are not authenticated', 'No token provided'));
        } catch (e: any) {
            return res.json(response.error(false, e.name, e.message));
        }
    }

    isUser(req: Request, res: Response, next: NextFunction): void {
        if (req.auth!.role === 'user' || req.auth!.role === 'admin') {
            next();
        } else {
            res.status(200).json(response.error(false, 'You are not admin or user', null));
        }
    }

    isAdmin(req: Request, res: Response, next: NextFunction): void {
        if (req.auth!.role === 'admin') {
            next();
        } else {
            res.status(200).json(response.error(false, 'You are not admin', null));
        }
    }
}


