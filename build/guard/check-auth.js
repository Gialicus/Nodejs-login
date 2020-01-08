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
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dontenv = __importStar(require("dotenv"));
dontenv.config();
function checkAuth(req, res, next) {
    try {
        const decoded = jsonwebtoken_1.default.verify(req.body.token, process.env.SECRET_KEY || 'secretKey');
        req.userData = decoded;
    }
    catch (error) {
        return res.status(401).json({
            message: 'AuthFailed'
        });
    }
    next();
}
exports.checkAuth = checkAuth;
