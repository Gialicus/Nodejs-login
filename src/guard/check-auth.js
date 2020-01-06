import jsonwebtoken from 'jsonwebtoken'
import * as dontenv from 'dotenv'
dontenv.config()
module.exports = (req, res, next) => {
    try {
        const decoded = jsonwebtoken.verify(req.body.token, process.env.SECRET_KEY || 'secretKey')
        req.userData = decoded;
    } catch (error){
        return res.status(401).json({
            message: 'AuthFailed'
        })
    }
    next();
}