import { Request, Response, Router } from 'express'
import User from '../models/User'
import Joi from 'joi';
import validationSchema from '../models/validation'
import bcrypt from 'bcrypt'
import jsonwebtoken from 'jsonwebtoken'
import * as dotenv from 'dotenv'
import { checkPermission } from '../guard/check-permission'
import { checkAuth } from '../guard/check-auth'


class baseController {
    router: Router;
    baseURL = process.env.BASE_URL || '/api/users';
    secretKey= process.env.SECRET_KEY || 'secretKey';

    constructor() {
        this.router = Router();
        this.routes();
    }
//get all User need Permission
    getAll = async (req: any,res: any) => {
        if (!checkPermission(req.userData)) {
            return res.status(200).json({error: 'permission denied'})
        }
        let users = await User.find()
        return res.status(200).json(users);
    }
//get One User by Id need Permission
    get = async (req: Request, res: Response) => {
        let user = await User.findById(req.params.id)
        return res.status(200).json(user);
    }
//Register new User no Permission needed
    add = async (req: Request, res: Response) => {
        const validObj = Joi.validate(req.body, validationSchema);
        if (validObj.error != null) {
            return res.status(500).json({ error: validObj.error })
        }
        let filter = { email: req.body.email }
        let check = await User.findOne(filter)
        if (check != null) {
            return res.status(500).json({ error: 'User Already Exist' })
        }
        bcrypt.hash(req.body.password, 10, (err, hash) => {
            if (err) {
                return res.status(500).json({ error: err });
            }
            else {
                let user = new User({
                    firstName: req.body.firstName,
                    lastName: req.body.lastName,
                    email: req.body.email,
                    password: hash
                });
                User.create(user);
                return res.json(user);
            }
        })

    }
//Delete User by Id need Permission
    delete = async (req: Request, res: Response) => {
        await User.findByIdAndDelete(req.params.id)
        return res.status(200).json({ result: "User was removed" });
    }
//Update User by Email need a Special Permission only for self
    update = async (req: Request, res: Response) => {
        let filter = {email: req.body.email}
        let user = new User({
            _id: req.body._id,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            password: await bcrypt.hash(req.body.password, 10)
        });
        let userDTO = await User.findOneAndUpdate( filter , user, { new: true })
        return res.status(200).json(userDTO)      
    }
//Login dont need Permission and Generate token
    login = async (req: Request, res: Response) => {
        let filter = { email: req.params.email }
        let check = await User.findOne(filter)
        if (check == null) {
            return res.status(401).json({ error: 'Auth failed' })
        }
        let valid = await bcrypt.compare(req.params.password, check.toObject().password)
        if (valid) {
            let token = jsonwebtoken.sign({
                email: check.toObject().email,
                id: check.toObject()._id,
                role: check.toObject().role
            }, this.secretKey, {
                expiresIn: '1h'
            })
            return res.status(200).json({
                message: 'Auth succes',
                token: token
            });
        } else {
            return res.status(401).json({ error: 'Auth failed' })
        }
    }
//Routes for User Controller
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
export default userController.router;