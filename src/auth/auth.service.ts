import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    constructor(
        private readonly jwtService: JwtService
    ) {
        super();
    }

    private readonly logger = new Logger('AuthServer');

    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async registerUser(registerUserDto: RegisterUserDto) {

        const { name, email, password } = registerUserDto;

        try {

            const user = await this.user.findUnique({
                where: {
                    email
                }
            })

            if (user) {
                throw new Error(
                    'User already exists'
                )
            }

            const newUser = await this.user.create({
                data: {
                    name,
                    email,
                    password: bcrypt.hashSync(password, 10)
                }
            })

            // elimino el passowrd del objeto
            const { password: __, ...rest } = newUser;

            return {
                user: rest,
                token: await this.signJWT(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {

        const { email, password } = loginUserDto;

        try {

            const user = await this.user.findUnique({
                where: {
                    email
                }
            })

            if (!user) {
                throw new Error(
                    'User/Email not valid credentials'
                )
            }

            const passwordValid = bcrypt.compareSync(password, user.password)

            if (!passwordValid) {
                throw new Error(
                    'User/Email not valid credentials'
                )
            }

            const { password: __, ...rest } = user;



            return {
                user: rest,
                token: await this.signJWT(rest)
            };


        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }

    }


    async verifyToken(token: string) {
        console.log(token)
        try {

            const { sub, iat, exp, ...user } = await this.jwtService.verify(token, {
                secret: envs.jwtSecret
            });

            return {
                user,
                token: await this.signJWT(user)
            }


        } catch (error) {
            console.log(error);
            throw new RpcException({
                status: 401,
                message: 'Token not valid'
            })
        }

    }

}
