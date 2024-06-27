import express, { Router } from 'express';
import AuthController from '../auth/auth.controller';
import AuthValidation from '../auth/auth.validation';
import UserController from './user.controller';

const router: Router = express.Router();

/**
 * User routing
 * 
 */
router.route('/addUser').post(AuthController.prototype.isAdmin, AuthValidation.addUserValidation, UserController.addUser);
router.route('/changePassword').put(AuthController.prototype.isUser, UserController.changePassword);
router.route('/updateProfile').put(AuthController.prototype.isUser, UserController.updateProfile);
router.route('/getProfile').get(AuthController.prototype.isUser, UserController.getProfile);
router.route('/getUsers').get(AuthController.prototype.isUser, UserController.getUsers);
router.route('/removeUser/:userId').delete(AuthController.prototype.isAdmin, UserController.removeUser);


router.post('/add-user', UserController.addUser);
router.get('/invite-signup', UserController.inviteSignupForm);
router.post('/invite-signup', UserController.inviteSignup);


export default router;
