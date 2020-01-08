import jsonwebtoken from 'jsonwebtoken'
import * as dontenv from 'dotenv'
dontenv.config()
export function checkAuth(req: any,res: any,next: any) {
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