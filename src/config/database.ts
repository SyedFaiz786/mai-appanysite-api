import mongoose from 'mongoose';

const connectDatabase = (): Promise<typeof mongoose> => {
    return mongoose.connect(process.env.DB_URL!, {})
        .then(() => {
            console.log('Mongoose connected');
            return mongoose;
        })
        .catch((error: mongoose.Error) => {
            console.error('Database connection error:', error.stack);
            throw error;
        });
};

export default connectDatabase;
