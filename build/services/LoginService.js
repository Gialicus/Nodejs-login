"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const User_1 = __importDefault(require("../models/User"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const validation_1 = __importDefault(require("../models/validation"));
const joi_1 = __importDefault(require("joi"));
class LoginService {
    constructor() {
        this.secretKey = process.env.SECRET_KEY || 'secretKey';
    }
    signIn(req) {
        return __awaiter(this, void 0, void 0, function* () {
            let filter = { email: req.params.email };
            let check = yield User_1.default.findOne(filter);
            console.log(check);
            if (check == null) {
                return null;
            }
            let valid = yield bcryptjs_1.default.compare(req.params.password, check.toObject().password);
            console.log(valid);
            if (valid) {
                let token = jsonwebtoken_1.default.sign({
                    email: check.toObject().email,
                    id: check.toObject()._id,
                    role: check.toObject().role
                }, this.secretKey, {
                    expiresIn: '1h'
                });
                console.log(token);
                return {
                    token: token
                };
            }
            else {
                return null;
            }
        });
    }
    signUp(req) {
        return __awaiter(this, void 0, void 0, function* () {
            const validObj = joi_1.default.validate(req.body, validation_1.default);
            if (validObj.error != null) {
                return null;
            }
            let filter = { email: req.body.email };
            let check = yield User_1.default.findOne(filter);
            if (check != null) {
                return null;
            }
            let hash = yield bcryptjs_1.default.hash(req.body.password, 10);
            let user = new User_1.default({
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                email: req.body.email,
                password: hash
            });
            return User_1.default.create(user);
        });
    }
}
exports.LoginService = LoginService;
