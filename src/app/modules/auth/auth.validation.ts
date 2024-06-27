import { Request, Response, NextFunction } from 'express';
import UserModel from '../user/user.model';

export default class AuthValidation {
    // 422 (Unprocessable Entity)
    static signupValidation(req: Request, res: Response, next: NextFunction): Response | void {
        const { username, email, password, phone } = req.body;

        if (!username || username.length === 0) {
            return res.status(422).json({ success: false, message: 'Username cannot be empty' });
        }
        if (!email || email.length === 0) {
            return res.status(422).json({ success: false, message: 'Email cannot be empty' });
        }
        if (!password || password.length === 0) {
            return res.status(422).json({ success: false, message: 'Password cannot be empty' });
        }
        if (!phone || phone.length === 0) {
            return res.status(422).json({ success: false, message: 'Phone number cannot be empty' });
        }

        next();
    }

    static forgotPasswordValidation(req: Request, res: Response, next: NextFunction): Response | void {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required' });
        }
        next();
    }

    static resetPasswordValidation(req: Request, res: Response, next: NextFunction): Response | void {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) {
            return res.status(400).json({ success: false, message: 'Token and new password are required' });
        }
        next();
    }

    static addUserValidation(req: Request, res: Response, next: NextFunction): Response | void {
        const { username, email, password, phone } = req.body;

        if (!username || username.length === 0) {
            return res.status(422).json({ success: false, message: 'Username cannot be empty' });
        }
        if (!email || email.length === 0) {
            return res.status(422).json({ success: false, message: 'Email cannot be empty' });
        }
        if (!password || password.length === 0) {
            return res.status(422).json({ success: false, message: 'Password cannot be empty' });
        }
        if (!phone || phone.length === 0) {
            return res.status(422).json({ success: false, message: 'Phone number cannot be empty' });
        }

        next();
    }

    // 422 (Unprocessable Entity)
    static loginValidation(req: Request, res: Response, next: NextFunction): Response | void {
        const { email, password } = req.body;

        if (!email || email.length === 0) {
            return res.status(422).json({ success: false, message: 'Email cannot be empty' });
        }
        if (!password || password.length === 0) {
            return res.status(422).json({ success: false, message: 'Password cannot be empty' });
        }

        next();
    }

    // Status 409: Check if an email exists in the database
    async checkEmailExistOrNot(email: string): Promise<{ success: boolean; message?: string }> {
        try {
            const response = await UserModel.findOne({ email });
            if (response !== null) {
                return {
                    success: false,
                    message: `${email} is already registered, please try another email`,
                };
            }
            return { success: true };
        } catch (e) {
            throw e;
        }
    }

    // Status 404: Check if a user exists based on email
    async checkUser({ email }: { email: string }): Promise<{ success: boolean; message?: string; data?: any }> {
        try {
            const response = await UserModel.findOne({ email });
            if (response) {
                return { success: true, data: response };
            }
            return { success: false, message: `${email} does not exist, please signup or try a valid registered email` };
        } catch (e) {
            throw e;
        }
    }
}
