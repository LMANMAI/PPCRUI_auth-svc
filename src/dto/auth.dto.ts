import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export enum ProfileType {
  PATIENT = 'PATIENT',
  CENTER_ADMIN = 'CENTER_ADMIN',
  ORG_ADMIN = 'ORG_ADMIN',
}

export class RegisterDto {
  @ApiProperty({ example: 'user@demo.com' })
  @IsEmail()
  email!: string;

  @ApiProperty({ minLength: 6 })
  @IsString()
  @MinLength(6)
  password!: string;

  @ApiProperty({ example: 'org-1' })
  @IsString()
  orgId!: string;

  @ApiProperty({ enum: ProfileType })
  @IsEnum(ProfileType)
  profileType!: ProfileType;

  @ApiProperty()
  @IsString()
  fullName?: string;

  @ApiProperty({ description: 'DNI' })
  @IsString()
  document!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  phone?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  staffFullName?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  centerId?: string;
}

export class LoginDto {
  @ApiProperty({ example: 'org-1' })
  @IsString()
  orgId!: string;

  @ApiProperty({
    description: 'Email o DNI',
    examples: ['user@demo.com', '34876543'],
  })
  @IsString()
  identifier!: string;

  @ApiProperty()
  @IsString()
  password!: string;

  @ApiPropertyOptional({ example: 'user@demo.com' })
  @IsOptional()
  @IsEmail()
  email?: string;
}
