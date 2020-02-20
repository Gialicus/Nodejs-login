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
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const dotenv = __importStar(require("dotenv"));
const check_permission_1 = require("../services/check-permission");
const check_auth_1 = require("../services/check-auth");
const LoginService_1 = require("../services/LoginService");
class baseController {
    constructor() {
        this.baseURL = process.env.BASE_URL || '/api/users';
        this.secretKey = process.env.SECRET_KEY || 'secretKey';
        this.loginService = new LoginService_1.LoginService();
        //get all User need Permission
        this.getAll = (req, res) => __awaiter(this, void 0, void 0, function* () {
            if (!check_permission_1.checkPermission(req.userData)) {
                return res.status(200).json({ error: 'permission denied' });
            }
            let users = yield User_1.default.find();
            return res.status(200).json(users);
        });
        //get One User by Id need Permission
        this.get = (req, res) => __awaiter(this, void 0, void 0, function* () {
            let user = yield User_1.default.findById(req.params.id);
            return res.status(200).json(user);
        });
        //Register new User no Permission needed
        this.add = (req, res) => __awaiter(this, void 0, void 0, function* () {
            let user = yield this.loginService.signUp(req);
            if (user) {
                return res.status(200).json(user);
            }
            else {
                return res.status(500).json({ error: 'Error during insert' });
            }
        });
        //Delete User by Id need Permission
        this.delete = (req, res) => __awaiter(this, void 0, void 0, function* () {
            yield User_1.default.findByIdAndDelete(req.params.id);
            return res.status(200).json({ result: "User was removed" });
        });
        //Update User by Email need a Special Permission only for self
        this.update = (req, res) => __awaiter(this, void 0, void 0, function* () {
            let filter = { email: req.body.email };
            let user = new User_1.default({
                _id: req.body._id,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                email: req.body.email,
                password: yield bcryptjs_1.default.hash(req.body.password, 10)
            });
            let userDTO = yield User_1.default.findOneAndUpdate(filter, user, { new: true });
            return res.status(200).json(userDTO);
        });
        //Login dont need Permission and Generate token
        this.login = (req, res) => __awaiter(this, void 0, void 0, function* () {
            let token = yield this.loginService.signIn(req);
            if (token) {
                return res.status(200).json(token);
            }
            else {
                return res.status(401).json({ error: 'Auth failed' });
            }
        });
        this.tryTimesheet = (req, res) => __awaiter(this, void 0, void 0, function* () {
            const list = req.body;
            return res.status(200).json(list);
        });
        this.router = express_1.Router();
        this.routes();
    }
    //Routes for User Controller
    routes() {
        //get all users
        this.router.get(this.baseURL, check_auth_1.checkAuth, this.getAll);
        //get user by id
        this.router.get(this.baseURL + '/:id', check_auth_1.checkAuth, this.get);
        //delete user
        this.router.delete(this.baseURL + '/:id', check_auth_1.checkAuth, this.delete);
        //update user
        this.router.put(this.baseURL, check_auth_1.checkAuth, this.update);
        //register new user
        this.router.post(this.baseURL, this.add);
        //user login
        this.router.get(this.baseURL + '/login/:email&:password', this.login);
        //try timesheet
        this.router.post('/api/timesheet', this.tryTimesheet);
    }
}
dotenv.config();
const userController = new baseController();
exports.default = userController.router;
