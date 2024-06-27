import { Request } from 'express';

declare module 'express-serve-static-core' {
    interface Request {
        user?: {
            _id: string;
            username: string;
            email: string;
            role: string;
            password?: string;
        };
        auth?: {
            id: string;
            username: string;
            email: string;
            role: string;
        };
        tokenObject?: {
            token: string;
        };
    }
}
