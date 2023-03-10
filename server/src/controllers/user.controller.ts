import express from "express";
import bcrypt from "bcrypt";
import { logger } from "../middlewares/logger";
import speakeasy from "speakeasy";
import nodemailer from "nodemailer";
import User, { IUserModel } from "../models/user.model";
import jwt from "jsonwebtoken";

export const registerUser = async (
  req: express.Request,
  res: express.Response
) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Missing email or password" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user: IUserModel = new User({
      email,
      password: hashedPassword,
    });
    await user.save();
    res.json({ message: "User registered successfully" });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const logUserIn = async (
  req: express.Request,
  res: express.Response
) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Missing email or password" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    if (!process.env.JWT_SECRET) {
      logger.error("JWT secret is not defined");
      process.exit(1);
    }

    const token = jwt.sign(
      { user: { _id: user._id, email: user.email } },
      process.env.JWT_SECRET
    );
    res.json({ token });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const generate2FAKey = async (
  req: express.Request,
  res: express.Response
) => {
  const secret = speakeasy.generateSecret();
  try {
    const user = await User.findById(res.locals.user._id);

    if (user) {
      (user as IUserModel).twoFactorSecret = secret.base32;
      await user.save();
    }
    const otpauthUrl = speakeasy.otpauthURL({
      secret: secret.ascii,
      label: "My Web App",
    });
    res.json({ otpauthUrl });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const verify2FA = async (
  req: express.Request,
  res: express.Response
) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ message: "Missing token" });
  }

  try {
    const user = await User.findById(res.locals.user._id);
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token,
    });

    if (!verified) {
      return res.status(401).json({ message: "Invalid token" });
    }

    res.json({ message: "Token verified" });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const send2FAVerificationEmail = async (
  req: express.Request,
  res: express.Response
) => {
  try {
    const user = await User.findById(res.locals.user._id);
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const token = speakeasy.totp({
      secret: user.twoFactorSecret,
      encoding: "base32",
    });

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: user.email,
      subject: "Your verification code",
      text: `Your verification code is: ${token}`,
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: "Verification code sent" });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const disable2FA = async (
  req: express.Request,
  res: express.Response
) => {
  try {
    const user = await User.findById(res.locals.user._id);
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    user.twoFactorSecret = "";
    await user.save();

    res.json({ message: "Two-factor authentication disabled" });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
};
