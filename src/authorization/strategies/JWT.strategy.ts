import { AuthenticationStrategy, TokenService } from '@loopback/authentication';
import { Request, HttpErrors } from '@loopback/rest';
import { UserProfile } from '@loopback/security';
import { TokenServiceBindings } from '../keys';
import { inject } from '@loopback/context';

export class JWTAuthenticationStrategy implements AuthenticationStrategy {

  /* Used by AuthenticationStrategyProvider to find the strategy
   which conforms to AuthenticationStrategy interface. */
  name: string = 'jwt';

  constructor(
    // It refers to JWTService.
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public tokenService: TokenService
  ) { }

  /*
    Used by AuthenticateActionProvider to authenticate the user.
  */
  async authenticate(request: Request): Promise<UserProfile | undefined> {
    const token: string = this.extractCredentials(request);
    try {
      const userProfile: UserProfile = await this.tokenService.verifyToken(token);
      return userProfile;
    } catch (err) {
      Object.assign(err, { code: 'INVALID_ACCESS_TOKEN', statusCode: 401 });
      throw err;
    }
  }

  extractCredentials(request: Request): string {
    const authHeaderValue = request.headers.authorization;
    if (!authHeaderValue) {
      throw new HttpErrors.Unauthorized('Authorization header not found.');
    }

    if (!authHeaderValue.startsWith('Bearer')) {
      throw new HttpErrors.Unauthorized(`Authorization header is not of type 'Bearer'.`);
    }

    //split the string into 2 parts: 'Bearer ' and the `xxx.yyy.zzz`
    const parts = authHeaderValue.split(' ');

    if (parts.length !== 2) {
      throw new HttpErrors.Unauthorized(
        `Authorization header value has too many parts. It must follow the pattern: 'Bearer xx.yy.zz' where xx.yy.zz is a valid JWT token.`,
      );
    }

    const token = parts[1];
    return token;
  }
}
