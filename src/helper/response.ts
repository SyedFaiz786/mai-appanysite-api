// Define interfaces for the response structures
interface SingleResponse {
    success: boolean;
    message: string;
    data: any;
}

interface ErrorResponse {
    success: boolean;
    message: string;
    error: string;
}

// Response utilities module
const responseUtils = {
    single(success: boolean = true, message: string = '', data: any = {}): SingleResponse {
        return {
            success,
            message,
            data,
        };
    },
    error(success: boolean = false, message: string = '', error: string = ''): ErrorResponse {
        return {
            success,
            message,
            error,
        };
    },
};

export default responseUtils;
