import express from 'express';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import { router } from './routes/user.router';
import { logger } from './middlewares/logger';

dotenv.config();

const app = express();
app.use(helmet());
app.use(cors());
app.use(router);
app.use(bodyParser.json());

mongoose.connect(process.env.MONGODB_URI as string);

const db = mongoose.connection;
db.on('error', logger.error.bind(logger.error));
db.once('open', () => {
  logger.info('Connected to MongoDB');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  logger.info(`Server listening on port ${port}`);
});
