import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { AuthDto } from './dto/auth.dto';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import * as argon2 from 'argon2';

@Injectable()
export class AuthService {
    constructor(
        private userService: UserService,
        private jwtService: JwtService,
        private configService: ConfigService,
    ) {}

    async signUp(createUserDto: CreateUserDto): Promise<any> {
        // Check if user exists
        const userExists = await this.userService.findOneByUsername(
          createUserDto.username,
        );
        if (userExists) {
          throw new BadRequestException('User already exists');
        }
    
        // Hash password
        const hash = await this.hashData(createUserDto.password);
        const newUser = await this.userService.create({
          ...createUserDto,
          password: hash,
        });
        const tokens = await this.getTokens(newUser.id, newUser.username);
        await this.updateRefreshToken(newUser.id, tokens.refreshToken);
        return tokens;
      }
    
        async signIn(data: AuthDto) {
        // Check if user exists
        const user = await this.userService.findOneByUsername(data.username);
        if (!user) throw new BadRequestException('User does not exist');
        const passwordMatches = await argon2.verify(user.password, data.password);
        if (!passwordMatches)
          throw new BadRequestException('Password is incorrect');
        const tokens = await this.getTokens(user.id, user.username);
        await this.updateRefreshToken(user.id, tokens.refreshToken);
        return tokens;
      }
    
        async logout(userId: number) {
        return this.userService.update(userId, { refreshToken: null });
      }
    
      hashData(data: string) {
        return argon2.hash(data);
      }
    
      async updateRefreshToken(userId: number, refreshToken: string) {
        const hashedRefreshToken = await this.hashData(refreshToken);
        await this.userService.update(userId, {
          refreshToken: hashedRefreshToken,
        });
      }
    
      async getTokens(userId: number, username: string) {
        const [accessToken, refreshToken] = await Promise.all([
          this.jwtService.signAsync(
            {
              sub: userId,
              username,
            },
            {
              secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
              expiresIn: '10s',
            },
          ),
          this.jwtService.signAsync(
            {
              sub: userId,
              username,
            },
            {
              secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
              expiresIn: '7d',
            },
          ),
        ]);
    
        return {
          accessToken,
          refreshToken,
        };
    }

    async refreshTokens(userId: number, refreshToken: string) {
      const user = await this.userService.findOne(userId);
      if (!user || !user.refreshToken)
        throw new ForbiddenException('Access Denied');
      const refreshTokenMatches = await argon2.verify(
        user.refreshToken,
        refreshToken,
      );
      if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');
      const tokens = await this.getTokens(user.id, user.username);
      await this.updateRefreshToken(user.id, tokens.refreshToken);
      return tokens;
    }

}
