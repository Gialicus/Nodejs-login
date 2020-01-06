"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const morgan_1 = __importDefault(require("morgan"));
const helmet_1 = __importDefault(require("helmet"));
const mongoose_1 = __importDefault(require("mongoose"));
const compression_1 = __importDefault(require("compression"));
const cors_1 = __importDefault(require("cors"));
const dotenv = __importStar(require("dotenv"));
const baseController_1 = __importDefault(require("./controller/baseController"));
class Server {
    constructor() {
        this.app = express_1.default();
        this.config();
        this.routes();
    }
    config() {
        //Mongodb connection
        const MONGO_URI = process.env.MONGODB_URL || '';
        const APP_PORT = process.env.PORT;
        mongoose_1.default.connect(MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useFindAndModify: false,
            useCreateIndex: true
        }).then(() => console.log('Mongodb is on'));
        //Settings
        this.app.set('port', APP_PORT);
        //Middelware
        this.app.use(morgan_1.default('dev'));
        this.app.use(express_1.default.json());
        this.app.use(express_1.default.urlencoded({ extended: false }));
        this.app.use(helmet_1.default());
        this.app.use(compression_1.default());
        this.app.use(cors_1.default());
    }
    start() {
        this.app.listen(this.app.get('port'), () => {
            console.log('Server Listening on port: ' + this.app.get('port'));
        });
    }
    routes() {
        this.app.use(baseController_1.default);
    }
}
dotenv.config();
const server = new Server();
server.start();
