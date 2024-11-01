import { Module } from '@nestjs/common';
import { NatsModule } from './transports/nats.module';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [AuthModule, NatsModule],
  controllers: [],
  providers: [],
})
export class AppModule { }
