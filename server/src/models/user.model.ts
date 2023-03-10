import mongoose from 'mongoose';

export interface IUser {
  email: string;
  password: string;
  twoFactorSecret?: string;
}

export interface IUserModel extends IUser, mongoose.Document {
  twoFactorSecret: string;
  comparePassword(password: string): Promise<boolean>;
}

const UserSchema = new mongoose.Schema<IUserModel>(
  {
    email: { type: String, required: true },
    password: { type: String, required: true },
    twoFactorSecret: { type: String },
  },
  { timestamps: true },
);

UserSchema.methods.comparePassword = async function (
  candidatePassword: string,
): Promise<boolean> {
  const user = this as IUserModel;
  return user.password === candidatePassword;
};

const User = mongoose.model<IUserModel>('User', UserSchema);

export default User;
