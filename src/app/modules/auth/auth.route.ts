// import express, { Request, Response, NextFunction, Router } from 'express';
// import AuthValidation from './auth.validation';
// import AuthController from './auth.controller';

// const router: Router = express.Router();
// const authController = new AuthController();

// router.route('/signup').post(
//     AuthValidation.signupValidation,
//     (req: Request, res: Response, next: NextFunction) => authController.signup(req, res)
// );

// router.route('/login').post(
//     AuthValidation.loginValidation,
//     (req: Request, res: Response, next: NextFunction) => authController.login(req, res, next),
//     (req: Request, res: Response, next: NextFunction) => authController.prepareToken(req, res, next),
//     (req: Request, res: Response, next: NextFunction) => authController.generateToken(req, res, next),
//     (req: Request, res: Response) => authController.sendToken(req, res)
// );

// router.route('/forgot-password').post(
//     (req: Request, res: Response) => authController.forgotPassword(req, res)
// );

// router.route('/reset-password').post(
//     (req: Request, res: Response) => authController.resetPassword(req, res)
// );

// // Serve the reset password form (could be a simple HTML form for this example)
// router.get('/reset-password', (req: Request, res: Response) => {
//     const token = req.query.token as string;
//     res.send(`
//         <form action="/reset-password" method="POST">
//             <input type="hidden" name="token" value="${token}" />
//             <label for="password">New Password:</label>
//             <input type="password" name="password" id="password" required />
//             <button type="submit">Reset Password</button>
//         </form>
//     `);
// });

// export default router;

import express, { Request, Response, NextFunction, Router } from 'express';
import AuthValidation from './auth.validation';
import AuthController from './auth.controller';
import methodOverride from 'method-override';

const router: Router = express.Router();
const authController = new AuthController();

// Method override middleware
router.use(methodOverride('_method'));

router.route('/signup').post(
    AuthValidation.signupValidation,
    (req: Request, res: Response, next: NextFunction) => authController.signup(req, res)
);

router.route('/login').post(
    AuthValidation.loginValidation,
    (req: Request, res: Response, next: NextFunction) => authController.login(req, res, next),
    (req: Request, res: Response, next: NextFunction) => authController.prepareToken(req, res, next),
    (req: Request, res: Response, next: NextFunction) => authController.generateToken(req, res, next),
    (req: Request, res: Response) => authController.sendToken(req, res)
);

router.post('/logout', (req, res) => authController.logout(req, res));

router.route('/forgot-password').post(
    (req: Request, res: Response) => authController.forgotPassword(req, res)
);

router.route('/reset-password').put(
    (req: Request, res: Response) => authController.resetPassword(req, res)
);


// Serve the reset password form (using POST method with method override to PUT)
router.get('/reset-password', (req: Request, res: Response) => {
    const token = req.query.token as string;
    res.send(`
        <form action="/api/auth/reset-password?_method=PUT" method="POST">
            <input type="hidden" name="token" value="${token}" />
            <label for="password">New Password:</label>
            <input type="password" name="password" id="password" required />
            <button type="submit">Reset Password</button>
        </form>
    `);
});

export default router;

