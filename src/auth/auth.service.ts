import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto } from './dto';
import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    console.log(createUserDto);
    try {
      const {password, ...userData} = createUserDto;

      const createdUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      await createdUser.save();
      // _ variable privada
      const {password:_, ...user} =  createdUser.toJSON();
      return user;
    } catch(error) {
      if(error.code === 11000)  throw new BadRequestException(`${createUserDto.email} already exists!`);
      else  throw new InternalServerErrorException('Something terrible happen!');
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string) {
    const {password, ...rest} = (await this.userModel.findById(id)).toJSON();
    return rest;
  }

  findUserByEmail(email: string): Promise<User[]> {
    return this.userModel.find({email});
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
  
  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {

    const {name, email, password} = registerUserDto;
    const users = await this.findUserByEmail(email);
    if(users.length > 0) throw new UnauthorizedException('El usuario ya existe')

    const user = await this.create({name, email, password});
    console.log({user});

    return {
      user: user,
      token: await this.getJwtToken({id: user._id})
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse>  {
    const {email, password} = loginDto;

    const user = await this.userModel.findOne({email: email});
    if(!user) throw new UnauthorizedException('Not valid credentials: email');
    if(!bcryptjs.compareSync(password, user.password))  throw new UnauthorizedException('Not valid credentials: password');

    const {password:_, ...rest} = user.toJSON();

    return {
      user: rest,
      token: await this.getJwtToken({id: user.id})
    };
  }

  getJwtToken (payload: JwtPayload) {
    const token = this.jwtService.signAsync(payload);
    return token;
  }
}
