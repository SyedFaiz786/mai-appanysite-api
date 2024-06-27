import bcrypt from 'bcryptjs';
import UserModel, { IUser } from './user.model';

const saltRounds = 10;

interface User {
    _id?: string;
    username: string;
    email: string;
    password: string;
    phone?: string;
    role?: string;
}

interface ChangePasswordResult {
    success: boolean;
    data?: IUser | null;
    message?: string;
}

class UserLib {
    static async getProfile(id: string): Promise<IUser | null> {
        try {
            return await UserModel.findById(id).select('-password').exec();
        } catch (e) {
            throw e;
        }
    }

    static async updateProfile(id: string, updateObject: Partial<User>): Promise<IUser | null> {
        try {
            return await UserModel.findByIdAndUpdate(id, updateObject, { new: true }).exec();
        } catch (e) {
            throw e;
        }
    }

    static async changePassword(id: string, oldPassword: string, newPassword: string): Promise<ChangePasswordResult> {
        try {
            const user = await UserModel.findOne({ _id: id });
            if (user) {
                const isMatched = await bcrypt.compare(oldPassword, user.password);
                if (isMatched) {
                    const hashed = bcrypt.hashSync(newPassword, saltRounds);
                    const updatedUser = await UserModel.findOneAndUpdate({ _id: id }, { $set: { password: hashed } }, { new: true }).exec();
                    return {
                        success: true,
                        data: updatedUser,
                    };
                }
                return {
                    success: false,
                    message: 'Password not matched',
                };
            }
            return {
                success: false,
                message: 'User not found',
            };
        } catch (e) {
            throw e;
        }
    }

    static async getUsers(): Promise<IUser[]> {
        try {
            return await UserModel.find().select('-password').exec();
        } catch (e) {
            throw e;
        }
    }

    static async removeUser(userId: string): Promise<boolean> {
        try {
            await UserModel.findByIdAndDelete(userId).exec();
            return true;
        } catch (e) {
            throw e;
        }
    }

    static async addUser(user: User): Promise<{ success: boolean; data?: IUser; message?: string }> {
        try {
            user.password = bcrypt.hashSync(user.password, saltRounds);
            user.role = 'user'; // Assuming 'user' role for all new users
            const found = await UserModel.findOne({ email: user.email }).exec();
            if (found) {
                return {
                    success: false,
                    message: 'Email already exists',
                };
            }
            const newUser = await UserModel.create(user);
            return {
                success: true,
                data: newUser,
            };
        } catch (e) {
            throw e;
        }
    }

    static async getUserByEmail(email: string): Promise<IUser | null> {
        try {
            return await UserModel.findOne({ email }).exec();
        } catch (e) {
            throw e;
        }
    }
    
}

export default UserLib;
