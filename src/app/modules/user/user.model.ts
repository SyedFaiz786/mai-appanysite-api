import { Schema, model, Document } from 'mongoose';

interface IUser extends Document {
    username: string;
    email: string;
    password: string;
    phone?: string;
    address?: string;
    role: string;
    resetPasswordToken?: string;
    resetPasswordExpires?: Date;
}

const userSchema = new Schema<IUser>({
    email: {
        type: String,
        required: true,
    },
    username: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    phone: {
        type: String, // Change to string
    },
    address: {
        type: String,
    },
    role: {
        type: String, // admin, user
        required: true,
    },
    resetPasswordToken: {
        type: String,
    },
    resetPasswordExpires: {
        type: Date,
    },
});

const UserModel = model<IUser>('User', userSchema);

export default UserModel;
export type { IUser };
