import express, { Request, Response, Router } from 'express';

const router: Router = express.Router();

router.route('/').get((req: Request, res: Response) => {
    res.json({ title: 'Welcome to the API' });
});

export default router;
