import express from 'express'
import morgan from 'morgan'
import helmet from 'helmet'
import mongoose from 'mongoose'
import compression from 'compression'
import cors from 'cors'
import * as dotenv from "dotenv";

import baseController from './controller/baseController'

class Server {
    public app: express.Application;

    constructor() {
        this.app = express();
        this.config();
        this.routes();
    }
    config() {
        //Mongodb connection
        const MONGO_URI = process.env.MONGODB_URL || '';
        const APP_PORT = process.env.PORT 
        mongoose.connect(MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useFindAndModify: false,
            useCreateIndex: true
        }).then( () => console.log('Mongodb is on') );
        //Settings
        this.app.set('port', APP_PORT)
        //Middelware
        this.app.use(morgan('dev'))
        this.app.use(express.json())
        this.app.use(express.urlencoded({extended: false}))
        this.app.use(helmet())
        this.app.use(compression())
        this.app.use(cors())
    }
    start() {
        this.app.listen(this.app.get('port'), () => {
            console.log('Server Listening on port: ' + this.app.get('port'))
        });

    }
    routes() {
        this.app.use(baseController)
    }
}
dotenv.config();
const server = new Server();
server.start();