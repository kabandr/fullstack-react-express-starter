import express from 'express';
import { logger } from './logger';
import jwt, { JwtPayload } from 'jsonwebtoken';

export const auth = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    if (!process.env.JWT_SECRET) {
      logger.error('JWT secret is not defined');
      process.exit(1);
    }

    const token = req.cookies.token;
    const decodedToken = jwt.verify(
      token,
      process.env.JWT_SECRET,
    ) as JwtPayload;
    res.locals.user = decodedToken.user;

    next();
  } catch (err) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
};
