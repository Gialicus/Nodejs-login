import User from '../models/User'
import bcrypt from 'bcryptjs'
import jsonwebtoken from 'jsonwebtoken'
import validationSchema from '../models/validation'
import Joi from 'joi';


export class LoginService {
    constructor() {
        
    }
    secretKey= process.env.SECRET_KEY || 'secretKey';

    async signIn(req: any) {
        let filter = { email: req.params.email }
        let check = await User.findOne(filter)
        console.log(check)
        if (check == null) {
            return null
        }
        let valid = await bcrypt.compare(req.params.password, check.toObject().password)
        console.log(valid)
        if (valid) {
            let token = jsonwebtoken.sign({
                email: check.toObject().email,
                id: check.toObject()._id,
                role: check.toObject().role
            }, this.secretKey, {
                expiresIn: '1h'
            })
            console.log(token)
            return {
                token: token
            };
        } else {
            return null
        }
    }
    async signUp(req: any) {
        const validObj = Joi.validate(req.body, validationSchema);
        
        if (validObj.error != null) {
            return null
        }
        let filter = { email: req.body.email }
        let check = await User.findOne(filter)

        if (check != null) {
            return null
        }
        let hash = await bcrypt.hash(req.body.password, 10);
        let user = new User({
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            password: hash
            });
        return User.create(user)      
        }
}