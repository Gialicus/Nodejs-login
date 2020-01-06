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
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const User_1 = __importDefault(require("../models/User"));
const joi_1 = __importDefault(require("joi"));
const validation_1 = __importDefault(require("../models/validation"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dotenv = __importStar(require("dotenv"));
const checkAuth = require('../guard/check-auth');
class baseController {
    constructor() {
        this.baseURL = process.env.BASE_URL || '/api/users';
        this.secretKey = process.env.SECRET_KEY || 'secretKey';
        this.getAll = (req, res) => __awaiter(this, void 0, void 0, function* () {
            if (!req.userData) {
                return res.status(401).json({ error: 'permission error' });
            }
            if (req.userData.role != 'ROLE_ADMIN') {
                return res.status(401).json({ error: 'permission error need Admin' });
            }
            let users = yield User_1.default.find();
            return res.status(200).json(users);
        });
        this.get = (req, res) => __awaiter(this, void 0, void 0, function* () {
            let user = yield User_1.default.findById(req.params.id);
            return res.status(200).json(user);
        });
        this.add = (req, res) => __awaiter(this, void 0, void 0, function* () {
            const validObj = joi_1.default.validate(req.body, validation_1.default);
            if (validObj.error != null) {
                return res.status(500).json({ error: validObj.error });
            }
            let filter = { email: req.body.email };
            let check = yield User_1.default.findOne(filter);
            if (check != null) {
                return res.status(500).json({ error: 'User Already Exist' });
            }
            bcrypt_1.default.hash(req.body.password, 10, (err, hash) => {
                if (err) {
                    return res.status(500).json({ error: err });
                }
                else {
                    let user = new User_1.default({
                        firstName: req.body.firstName,
                        lastName: req.body.lastName,
                        email: req.body.email,
                        password: hash
                    });
                    User_1.default.create(user);
                    return res.json(user);
                }
            });
        });
        this.delete = (req, res) => __awaiter(this, void 0, void 0, function* () {
            yield User_1.default.findByIdAndDelete(req.params.id);
            return res.status(200).json({ result: "User was removed" });
        });
        this.update = (req, res) => __awaiter(this, void 0, void 0, function* () {
            let filter = { email: req.body.email };
            let user = new User_1.default({
                _id: req.body._id,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                email: req.body.email,
                password: yield bcrypt_1.default.hash(req.body.password, 10)
            });
            let userDTO = yield User_1.default.findOneAndUpdate(filter, user, { new: true });
            return res.status(200).json(userDTO);
        });
        this.login = (req, res) => __awaiter(this, void 0, void 0, function* () {
            let filter = { email: req.params.email };
            let check = yield User_1.default.findOne(filter);
            if (check == null) {
                return res.status(401).json({ error: 'Auth failed' });
            }
            let valid = yield bcrypt_1.default.compare(req.params.password, check.toObject().password);
            if (valid) {
                let token = jsonwebtoken_1.default.sign({
                    email: check.toObject().email,
                    id: check.toObject()._id,
                    role: check.toObject().role
                }, this.secretKey, {
                    expiresIn: '1h'
                });
                return res.status(200).json({
                    message: 'Auth succes',
                    token: token
                });
            }
            else {
                return res.status(401).json({ error: 'Auth failed' });
            }
        });
        this.router = express_1.Router();
        this.routes();
    }
    routes() {
        //get all users
        this.router.get(this.baseURL, checkAuth, this.getAll);
        //get user by id
        this.router.get(this.baseURL + '/:id', checkAuth, this.get);
        //delete user
        this.router.delete(this.baseURL + '/:id', checkAuth, this.delete);
        //update user
        this.router.put(this.baseURL, checkAuth, this.update);
        //register new user
        this.router.post(this.baseURL, this.add);
        //user login
        this.router.get(this.baseURL + '/login/:email&:password', this.login);
    }
}
dotenv.config();
const userController = new baseController();
exports.default = userController.router;