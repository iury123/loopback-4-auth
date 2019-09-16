import { TokenService } from "@loopback/authentication";
import { UserProfile } from "@loopback/security";
import { TokenServiceConstants } from "../keys";
import { HttpErrors } from "@loopback/rest";
import { promisify } from "util";

const jwt = require('jsonwebtoken');
const signAsync = promisify(jwt.sign);
const verifyAsync = promisify(jwt.verify);

export class JWTService implements TokenService {

  async verifyToken(token: string): Promise<UserProfile> {
    if (!token) {
      throw new HttpErrors.Unauthorized(
        `Error verifying token: 'token' is null`,
      );
    }

    let userProfile: UserProfile;

    try {
      // decode user profile from token
      const decryptedToken = await verifyAsync(token, TokenServiceConstants.TOKEN_SECRET_VALUE);
      // don't copy over  token field 'iat' and 'exp', nor 'email' to user profile
      userProfile = Object.assign(
        { id: '', name: '' },
        { id: decryptedToken.id, name: decryptedToken.name },
      );
    } catch (error) {
      throw new HttpErrors.Unauthorized(
        `Error verifying token: ${error.message}`,
      );
    }

    return userProfile;
  }

  async generateToken(userProfile: UserProfile): Promise<string> {
    if (!userProfile) {
      throw new HttpErrors.Unauthorized(
        'Error generating token: userProfile is null',
      );
    }

    // Generate a JSON Web Token
    let token: string;
    try {
      token = await signAsync(userProfile, TokenServiceConstants.TOKEN_SECRET_VALUE, {
        expiresIn: Number(TokenServiceConstants.TOKEN_EXPIRES_IN_VALUE),
      });
    } catch (error) {
      throw new HttpErrors.Unauthorized(`Error encoding token: ${error}`);
    }

    return token;
  }

}
