import 'dotenv/config';
import * as joi from 'joi';

interface EnvsVars {
    NATS_SERVERS: string[];
    JWT_SECRET: string;
}

const envSchema = joi.object({
    NATS_SERVERS: joi.array().items(joi.string()).required(),
    JWT_SECRET: joi.string().required()
})
    .unknown(true);

const { error, value } = envSchema.validate({
    ...process.env,
    NATS_SERVERS: process.env.NATS_SERVERS.split(',')
})

if (error) {
    throw new Error(`Config validation error: ${error.message}`)
}

const envVars: EnvsVars = value;

export const envs = {
    natsServers: envVars.NATS_SERVERS,
    jwtSecret: envVars.JWT_SECRET
}