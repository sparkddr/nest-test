import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    // generate the password hash
    const hash = await argon.hash(dto.password);
    //save the new use in the db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      delete user.hash;
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('User already exists');
        }
      }
      throw error;
    }
  }
  async signin(dto: AuthDto) {
    // find the user by email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    // if user does not exist, throw an exception
    if (!user) {
      throw new ForbiddenException('User not found');
    }
    // compare password
    const passwordMatch = await argon.verify(user.hash, dto.password);
    // if password does not match, throw an exception
    if (!passwordMatch) {
      throw new ForbiddenException('Password does not match');
    }
    delete user.hash;
    // send back the user
    return user;
  }
}
