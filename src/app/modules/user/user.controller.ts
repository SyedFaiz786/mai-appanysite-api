import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import path from 'path';
import fs from 'fs';
import response from '../../../helper/response';
import UserLib from './user.lib';
import { sendEmail } from '../auth/emailService';
import { IUser } from './user.model';

const configPath = path.resolve(__dirname, '../../../config/config.json');

let config;

try {
    const rawData = fs.readFileSync(configPath, 'utf-8');
    config = JSON.parse(rawData);
} catch (error) {
    console.error('Failed to load config file:', error);
    throw error;
}

const secretKey: string = config.development.JWTsecret;

class UserController {
    // static async addUser(req: Request, res: Response): Promise<Response> {
    //     try {
    //         const token = req.headers['x-auth-token'] as string;
    //         if (!token) {
    //             return res.status(401).json(response.error(false, 'No token provided'));
    //         }

    //         let decoded;
    //         try {
    //             decoded = jwt.verify(token, secretKey) as { id: string, username: string, email: string, role: string };
    //         } catch (e) {
    //             return res.status(403).json(response.error(false, 'Failed to authenticate token'));
    //         }

    //         if (decoded.role !== 'admin') {
    //             return res.status(403).json(response.error(false, 'You are not authorized to add users'));
    //         }

    //         const user = req.body;
    //         const userData = await UserLib.addUser(user);
    //         if (userData.success) {
    //             return res.status(201).json(response.single(true, 'New User Created', userData.data));
    //         }
    //         return res.status(200).json(response.error(false, userData.message));
    //     } catch (e: any) {
    //         return res.status(500).json(response.error(false, 'An error occurred', e.message));
    //     }
    // }

    static async addUser(req: Request, res: Response): Promise<Response> {
        try {
            const token = req.headers['x-auth-token'] as string;
            if (!token) {
                return res.status(401).json(response.error(false, 'No token provided'));
            }

            let decoded;
            try {
                decoded = jwt.verify(token, secretKey) as { id: string, username: string, email: string, role: string };
            } catch (e) {
                return res.status(403).json(response.error(false, 'Failed to authenticate token'));
            }

            if (decoded.role !== 'admin') {
                return res.status(403).json(response.error(false, 'You are not authorized to add users'));
            }

            const { email } = req.body;
            const existingUser = await UserLib.getUserByEmail(email);

            if (existingUser) {
                return res.status(200).json(response.error(false, 'User already exists'));
            }

            const inviteToken = jwt.sign({ email }, secretKey, { expiresIn: '1h' });
            const invitationLink = `http://${config.development.server.host}:${config.development.server.port}/api/v1/user/invite-signup?token=${inviteToken}`;

            const emailResponse = await sendEmail(email, 'Invitation to Signup', `Click here to sign up: ${invitationLink}`);

            if (emailResponse.success) {
                return res.status(200).json(response.single(true, 'Invitation email sent', null));
            } else {
                return res.status(500).json(response.error(false, emailResponse.message, emailResponse.error));
            }
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }


    static async changePassword(req: Request, res: Response): Promise<Response> {
        try {
            const { id } = req.auth!;
            const { oldPassword, newPassword } = req.body;
            const user = await UserLib.changePassword(id, oldPassword, newPassword);
            if (user.success) {
                return res.status(200).json(response.single(true, 'Password changed successfully', user.data));
            }
            return res.status(200).json(response.error(false, user.message));
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }

    static async updateProfile(req: Request, res: Response): Promise<Response> {
        try {
            const updateObject = req.body;
            const data = await UserLib.updateProfile(req.auth!.id, updateObject);
            return res.status(200).json(response.single(true, 'Profile updated successfully', data));
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }

    static async getProfile(req: Request, res: Response): Promise<Response> {
        try {
            const { id } = req.auth!;
            const data = await UserLib.getProfile(id) as IUser;
            return res.status(200).json(response.single(true, `Welcome ${data.username}`, data));
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }

    static async getUsers(req: Request, res: Response): Promise<Response> {
        try {
            const users = await UserLib.getUsers();
            return res.status(200).json(response.single(true, 'Users fetched successfully', users));
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }

    static async removeUser(req: Request, res: Response): Promise<Response> {
        try {
            const { userId } = req.params;
            await UserLib.removeUser(userId);
            return res.status(200).json(response.single(true, 'User removed successfully', 'User removed successfully'));
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }

    static async inviteSignupForm(req: Request, res: Response): Promise<void> {
        const token = req.query.token as string;
        res.send(`
            <form action="/api/auth/invite-signup" method="POST">
                <input type="hidden" name="token" value="${token}" />
                <label for="username">Username:</label>
                <input type="text" name="username" id="username" required />
                <label for="password">Password:</label>
                <input type="password" name="password" id="password" required />
                <label for="phone">Phone:</label>
                <input type="text" name="phone" id="phone" required />
                <button type="submit">Sign Up</button>
            </form>
        `);
    }

    static async inviteSignup(req: Request, res: Response): Promise<Response> {
        try {
            const { token, username, password, phone } = req.body;

            let decoded;
            try {
                decoded = jwt.verify(token, secretKey) as { email: string };
            } catch (e) {
                return res.status(403).json(response.error(false, 'Invalid or expired token'));
            }

            const user = {
                username,
                email: decoded.email,
                password,
                phone,
                role: 'user',
            };

            const userData = await UserLib.addUser(user);
            if (userData.success) {
                return res.status(201).json(response.single(true, 'User signed up successfully', userData.data));
            }
            return res.status(200).json(response.error(false, userData.message));
        } catch (e: any) {
            return res.status(500).json(response.error(false, 'An error occurred', e.message));
        }
    }
}



export default UserController;
